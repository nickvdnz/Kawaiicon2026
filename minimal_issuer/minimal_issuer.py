#!/usr/bin/env python3
"""
Minimal OID4VCI Issuer — single-file ISO mdoc issuer.

Issues one ISO 18013-5 / 23220 mdoc credential (default: org.iso.23220.photoid.1 with
age_over_18) over OID4VCI 1.0, pre-authorized code flow only. No tx_code, no auth-code
flow, no encryption, no status lists, no batch — the smallest thing a wallet will accept.

Wallet makes these requests (after scanning the QR on GET /):
  1. GET  /offer/{id}                                — credential offer (by reference)
  2. GET  /.well-known/openid-credential-issuer      — issuer metadata
  3. GET  /.well-known/oauth-authorization-server    — token endpoint
  4. POST /token                                     — pre-authorized code → access token
  5. POST /nonce                                     — c_nonce for the proof
  6. POST /credential                                — proof JWT → base64url IssuerSigned

Keys: an IACA + DSC are generated into keys/ on first run, unless the config points
dsc_key/dsc_cert at existing files. Wallets only trust the result if they trust the IACA.

Usage:
  python minimal_issuer.py

Config: minimal_issuer_config.json
Dependencies: pip install flask pyjwt cryptography cbor2 qrcode[pil]
"""

import json, os, secrets, hashlib, base64, datetime, time
from io import BytesIO
from urllib.parse import quote

import cbor2, qrcode
import jwt as pyjwt
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = os.path.dirname(os.path.abspath(__file__))
PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

app = Flask(__name__)
config = dsc_key = dsc_der = None
offers = {}   # offer_id -> {"code", "issued"}
codes = {}    # pre-authorized code -> offer_id   (single use)
tokens = {}   # access token -> (offer_id, expiry)
nonces = {}   # c_nonce -> expiry                 (single use)


# ---------------------------------------------------------------- keys --------
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, config["country"]),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _generate_keys(keys_dir):
    """Self-made IACA (CA root) + DSC signed by it, with the ISO 18013-5 DSC EKU."""
    os.makedirs(keys_dir, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    iaca_k, dsc_k = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    iaca_ski = x509.SubjectKeyIdentifier.from_public_key(iaca_k.public_key())
    iaca = (x509.CertificateBuilder()
            .subject_name(_name(f"{config['issuer_name']} IACA")).issuer_name(_name(f"{config['issuer_name']} IACA"))
            .public_key(iaca_k.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(iaca_ski, critical=False)
            .sign(iaca_k, hashes.SHA256()))
    dsc = (x509.CertificateBuilder()
           .subject_name(_name(f"{config['issuer_name']} DSC")).issuer_name(iaca.subject)
           .public_key(dsc_k.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=455))
           .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
           .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]), critical=True)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(iaca_ski), critical=False)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(dsc_k.public_key()), critical=False)
           .sign(iaca_k, hashes.SHA256()))
    pem_key = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
    for fname, data in (("iaca.key", pem_key(iaca_k)), ("dsc.key", pem_key(dsc_k)),
                        ("iaca.crt", iaca.public_bytes(serialization.Encoding.PEM)),
                        ("dsc.crt", dsc.public_bytes(serialization.Encoding.PEM))):
        with open(os.path.join(keys_dir, fname), "wb") as f:
            f.write(data)
    print(f"[init] Generated IACA + DSC in {keys_dir}/ — give wallets/verifiers iaca.crt")


def load_config():
    global config, dsc_key, dsc_der
    with open(os.path.join(HERE, "minimal_issuer_config.json")) as f:
        config = json.load(f)
    keys_dir = os.path.join(HERE, config.get("keys_dir", "keys"))
    key_path = config.get("dsc_key") or os.path.join(keys_dir, "dsc.key")
    cert_path = config.get("dsc_cert") or os.path.join(keys_dir, "dsc.crt")
    if not (os.path.exists(key_path) and os.path.exists(cert_path)):
        if config.get("dsc_key"):
            raise SystemExit(f"dsc_key/dsc_cert configured but not found: {key_path}, {cert_path}")
        _generate_keys(keys_dir)
    with open(key_path, "rb") as f:
        dsc_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    dsc_der = cert.public_bytes(serialization.Encoding.DER)
    print(f"[init] Issuer: {config['base_url']}  DSC: {cert.subject.rfc4514_string()}")
    print(f"[init] Issues: {config['doctype']} as '{config['credential_configuration_id']}'")


# ---------------------------------------------------------------- mdoc --------
def _claim_value(v):
    """JSON → CBOR: {"full-date": "YYYY-MM-DD"} → tag 1004, {"file": path} → bytes, else as-is."""
    if isinstance(v, dict) and "full-date" in v:
        return cbor2.CBORTag(1004, v["full-date"])
    if isinstance(v, dict) and "file" in v:
        with open(os.path.join(HERE, v["file"]), "rb") as f:
            return f.read()
    return v


def _tdate(dt):
    return cbor2.CBORTag(0, dt.strftime("%Y-%m-%dT%H:%M:%SZ"))


def build_issuer_signed(device_jwk):
    """IssuerSigned = {nameSpaces, issuerAuth} per ISO 18013-5 §8.3.2.1.2.2 / §9.1.2.4."""
    ns = config["namespace"]
    items, digests = [], {}
    for digest_id, (name, value) in enumerate(config["claims"].items()):
        item_bytes = cbor2.dumps({"digestID": digest_id, "random": secrets.token_bytes(16),
                                  "elementIdentifier": name, "elementValue": _claim_value(value)})
        tagged = cbor2.CBORTag(24, item_bytes)
        items.append(tagged)
        digests[digest_id] = hashlib.sha256(cbor2.dumps(tagged)).digest()

    b64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    device_key = {1: 2, -1: 1, -2: b64(device_jwk["x"]), -3: b64(device_jwk["y"])}   # COSE_Key EC2 P-256
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    mso = {"version": "1.0", "digestAlgorithm": "SHA-256", "valueDigests": {ns: digests},
           "deviceKeyInfo": {"deviceKey": device_key}, "docType": config["doctype"],
           "validityInfo": {"signed": _tdate(now), "validFrom": _tdate(now),
                            "validUntil": _tdate(now + datetime.timedelta(days=config.get("validity_days", 365)))}}

    # COSE_Sign1 over MobileSecurityObjectBytes = #6.24(bstr .cbor MSO), x5chain = DSC (label 33)
    protected = cbor2.dumps({1: -7})                                   # alg ES256
    payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    r, s = decode_dss_signature(dsc_key.sign(to_sign, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return cbor2.dumps({"nameSpaces": {ns: items}, "issuerAuth": [protected, {33: dsc_der}, payload, signature]})


# ---------------------------------------------------------------- metadata ----
@app.get("/.well-known/openid-credential-issuer")
def issuer_metadata():
    base = config["base_url"]
    return jsonify({
        "credential_issuer": base,
        "credential_endpoint": f"{base}/credential",
        "nonce_endpoint": f"{base}/nonce",
        "display": [{"name": config["issuer_name"]}],
        "credential_configurations_supported": {config["credential_configuration_id"]: {
            "format": "mso_mdoc",
            "doctype": config["doctype"],
            "cryptographic_binding_methods_supported": ["cose_key"],
            "credential_signing_alg_values_supported": [-7],
            "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
            "credential_metadata": {
                "display": [{"name": config.get("credential_name", config["doctype"])}],
                "claims": [{"path": [config["namespace"], c]} for c in config["claims"]]}}}})


@app.get("/.well-known/oauth-authorization-server")
def as_metadata():
    base = config["base_url"]
    return jsonify({"issuer": base, "token_endpoint": f"{base}/token",
                    "grant_types_supported": [PRE_AUTH],
                    "pre-authorized_grant_anonymous_access_supported": True})


# ---------------------------------------------------------------- offer -------
def new_offer():
    offer_id, code = secrets.token_urlsafe(12), secrets.token_urlsafe(24)
    offers[offer_id] = {"code": code, "issued": False}
    codes[code] = offer_id
    offer_uri = f"{config['base_url']}/offer/{offer_id}"
    return offer_id, f"openid-credential-offer://?credential_offer_uri={quote(offer_uri, safe='')}"


@app.get("/offer/<offer_id>")
def get_offer(offer_id):
    o = offers.get(offer_id)
    if not o:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"credential_issuer": config["base_url"],
                    "credential_configuration_ids": [config["credential_configuration_id"]],
                    "grants": {PRE_AUTH: {"pre-authorized_code": o["code"]}}})


@app.get("/new-offer")
def new_offer_json():
    """For scripts/CLI wallets: a fresh offer deep link as JSON."""
    offer_id, link = new_offer()
    return jsonify({"offer_id": offer_id, "credential_offer": link})


@app.get("/status/<offer_id>")
def status(offer_id):
    return jsonify({"issued": offers.get(offer_id, {}).get("issued", False)})


@app.get("/")
def index():
    offer_id, link = new_offer()
    buf = BytesIO()
    qrcode.make(link, border=4).save(buf, format="PNG")
    qr = base64.b64encode(buf.getvalue()).decode()
    print(f"[offer] {link}")
    return f"""<!doctype html><title>{config['issuer_name']}</title>
<body style="font-family:sans-serif;text-align:center;padding:2em">
<h2>{config['issuer_name']}</h2><p>Scan with a wallet to receive <b>{config['doctype']}</b></p>
<img src="data:image/png;base64,{qr}" width="320"><p id="s">Waiting for wallet…</p>
<p style="font-size:12px;word-break:break-all;color:#666">{link}</p>
<script>setInterval(async()=>{{const r=await(await fetch('/status/{offer_id}')).json();
if(r.issued)document.getElementById('s').textContent='✅ Credential issued';}},2000)</script>"""


# ---------------------------------------------------------------- token -------
def _no_store(resp, status=200):
    resp.headers["Cache-Control"] = "no-store"
    return resp, status


@app.post("/token")
def token():
    f = request.form
    if f.get("grant_type") != PRE_AUTH:
        return _no_store(jsonify({"error": "unsupported_grant_type"}), 400)
    offer_id = codes.pop(f.get("pre-authorized_code", ""), None)          # single use
    if not offer_id:
        return _no_store(jsonify({"error": "invalid_grant"}), 400)
    access_token = secrets.token_urlsafe(32)
    tokens[access_token] = (offer_id, time.time() + 300)
    # c_nonce here is pre-1.0 behaviour (1.0 final moved it to /nonce). Kept so wallets that
    # never call the nonce endpoint still work; 1.0 wallets ignore it.
    return _no_store(jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 300,
                              "c_nonce": _new_nonce()}))


def _new_nonce():
    c_nonce = secrets.token_urlsafe(24)
    nonces[c_nonce] = time.time() + 300
    return c_nonce


@app.post("/nonce")
def nonce():
    return _no_store(jsonify({"c_nonce": _new_nonce()}))


# ---------------------------------------------------------------- credential --
def _verify_proof(proof_jwt):
    """Key proof per OID4VCI 1.0 Appendix F.1. Returns the holder's public JWK."""
    header = pyjwt.get_unverified_header(proof_jwt)
    holder_jwk = header.get("jwk")
    if header.get("typ") != "openid4vci-proof+jwt" or header.get("alg") != "ES256" or not holder_jwk or "d" in holder_jwk:
        raise ValueError("invalid_proof")
    claims = pyjwt.decode(proof_jwt, pyjwt.PyJWK(holder_jwk).key, algorithms=["ES256"],
                          audience=config["base_url"], options={"require": ["iat", "nonce"]})
    if abs(time.time() - claims["iat"]) > 300:
        raise ValueError("invalid_proof")
    if nonces.pop(claims["nonce"], 0) < time.time():                      # single use + expiry
        raise ValueError("invalid_nonce")
    return holder_jwk


@app.post("/credential")
def credential():
    auth = request.headers.get("Authorization", "")
    entry = tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
    if not entry or entry[1] < time.time():
        return jsonify({"error": "invalid_token"}), 401
    body = request.get_json(silent=True) or {}
    if body.get("credential_configuration_id") != config["credential_configuration_id"]:
        return jsonify({"error": "unknown_credential_configuration"}), 400
    proofs = (body.get("proofs") or {}).get("jwt") or ([body["proof"]["jwt"]] if "proof" in body else [])
    if len(proofs) != 1:
        return jsonify({"error": "invalid_proof", "error_description": "exactly one jwt proof required"}), 400
    try:
        holder_jwk = _verify_proof(proofs[0])
    except Exception as e:
        err = str(e) if str(e) in ("invalid_proof", "invalid_nonce") else "invalid_proof"
        return jsonify({"error": err, "error_description": str(e)}), 400

    issuer_signed = build_issuer_signed(holder_jwk)
    del tokens[auth[7:]]                                                   # one credential per token
    offers[entry[0]]["issued"] = True
    print(f"[issued] {config['doctype']} for offer {entry[0]} ({len(issuer_signed)} bytes)")
    return _no_store(jsonify({"credentials": [
        {"credential": base64.urlsafe_b64encode(issuer_signed).rstrip(b"=").decode()}]}))


if __name__ == "__main__":
    load_config()
    app.run(host="0.0.0.0", port=config.get("port", 8090))
