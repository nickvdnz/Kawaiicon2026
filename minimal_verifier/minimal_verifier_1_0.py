#!/usr/bin/env python3
"""
Minimal OID4VP 1.0 Verifier — age verification with full mdoc verification.

OpenID for Verifiable Presentations 1.0 (Final) + ISO 18013-5 mdoc (OID4VP 1.0 Appendix B.2).
What OID4VP 1.0 changes compared with pre-1.0 (draft) verifiers:

  Request   client_id carries its Client Identifier Prefix ("x509_san_dns:<dns>"), no separate
            client_id_scheme; DCQL query (dcql_query) instead of presentation_definition;
            client_metadata uses vp_formats_supported + encrypted_response_enc_values_supported;
            wallet invocation uses openid4vp://.
  Response  direct_post.jwt (JWE, alg = the JWK's alg, enc from metadata); vp_token is an object
            keyed by DCQL credential query id; no presentation_submission.
  deviceAuth  verified against the one SessionTranscript 1.0 defines (Appendix B.2.6.1):
            [null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwkThumbprint,
            response_uri]))]].

Checks on every presentation: issuerAuth signature, DSC chains to a trusted IACA (trusted_iacas/),
IACA + DSC validity, MSO validFrom/validUntil, docType, element digests, deviceAuth signature
(holder binding + nonce/session binding), returned claims vs the DCQL query.

Wallet makes exactly 2 requests:
  1. GET  /v2/presentations/sessions/{sid}/requests/{rid}  — signed request object (JWT)
  2. POST /v2/presentations/sessions/response              — encrypted Authorization Response

Usage:
  python minimal_verifier_1_0.py [--config verifier_config.json]

Config: verifier_config.json (client_id is the bare DNS name; the prefix is added here)
Dependencies: pip install flask pyjwt cryptography jwcrypto cbor2 qrcode[pil]
"""

import json, uuid, base64, hashlib, os, glob, argparse, html
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import quote

import cbor2, qrcode
import jwt as pyjwt
from flask import Flask, request, Response, jsonify
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from jwcrypto import jwk, jwe

app = Flask(__name__)
sessions = {}       # sid -> {rid(nonce), jwt, state, result, verification}
RECENT = []         # last 20 results, newest last — shown at /last
signing_key = cert_der = enc_key = config = None
trusted_iacas = []  # x509.Certificate

DEFAULT_DCQL = {"credentials": [{
    "id": "photoid", "format": "mso_mdoc",
    "meta": {"doctype_value": "org.iso.23220.photoid.1"},
    "claims": [{"path": ["org.iso.23220.1", "age_over_18"], "intent_to_retain": False}]}]}


def load_config(path):
    global config, signing_key, cert_der, enc_key
    base_dir = os.path.dirname(os.path.abspath(path))
    with open(path) as f:
        config = json.load(f)
    rel = lambda p: p if os.path.isabs(p) else os.path.join(base_dir, p)

    with open(rel(config["signing_key"]), "rb") as f:
        signing_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(rel(config["signing_cert"]), "rb") as f:
        cert_der = x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)

    enc_path = rel(config.get("encryption_key", "enc_jwk.json"))
    if os.path.exists(enc_path):
        with open(enc_path) as f:
            enc_key = jwk.JWK(**json.load(f))
    else:
        enc_key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(uuid.uuid4()))
        enc_key.update(use="enc", alg="ECDH-ES")              # 1.0 §8.3: alg MUST be in the JWK
        with open(enc_path, "w") as f:
            json.dump(json.loads(enc_key.export(private_key=True)), f, indent=2)
        print("[init] Generated encryption key")

    vical_dir = rel(config.get("vical_dir", "trusted_iacas"))
    for p in sorted(glob.glob(os.path.join(vical_dir, "*"))):
        try:
            data = open(p, "rb").read()
            trusted_iacas.append(x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data
                                 else x509.load_der_x509_certificate(data))
        except Exception as e:
            print(f"[init] Skipping {p}: {e}")
    print(f"[init] Trusted IACAs: {len(trusted_iacas)} from {vical_dir}/"
          + ("" if trusted_iacas else "  — issuer trust will FAIL until you add one"))
    print(f"[init] client_id: {client_id()}")
    print(f"[init] base_url:  {config['base_url']}")


def client_id():
    """1.0 client_id = Client Identifier Prefix + value (e.g. x509_san_dns:verifier.example)."""
    cid = config["client_id"]
    return cid if ":" in cid else f"{config.get('client_id_prefix', 'x509_san_dns')}:{cid}"


def response_uri():
    return config["base_url"].rstrip("/") + "/v2/presentations/sessions/response"


def dcql_query():
    return config.get("dcql_query") or DEFAULT_DCQL


def enc_public_jwk():
    return json.loads(enc_key.export_public())


def jwk_thumbprint_bytes(j):
    """RFC 7638 SHA-256 thumbprint as raw bytes (OID4VP 1.0 B.2.6.1: jwkThumbprint = bstr)."""
    members = {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]}
    return hashlib.sha256(json.dumps(members, separators=(",", ":"), sort_keys=True).encode()).digest()


# ── Request ──────────────────────────────────────────────────

def create_session():
    sid, rid = str(uuid.uuid4()), str(uuid.uuid4())
    payload = {
        "aud": "https://self-issued.me/v2",
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "client_id": client_id(),
        "response_uri": response_uri(),
        "nonce": rid,
        "state": sid,
        "dcql_query": dcql_query(),
        "client_metadata": {
            "jwks": {"keys": [enc_public_jwk()]},
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": {"mso_mdoc": {"issuerauth_alg_values": [-7, -9],
                                                  "deviceauth_alg_values": [-7, -9]}},
        },
    }
    jwt_token = pyjwt.encode(payload, signing_key, algorithm="ES256",
                             headers={"typ": "oauth-authz-req+jwt",
                                      "x5c": [base64.b64encode(cert_der).decode()]})
    request_uri = f"{config['base_url']}/v2/presentations/sessions/{sid}/requests/{rid}"
    scheme = config.get("wallet_scheme", "openid4vp://")
    deeplink = f"{scheme}?client_id={quote(client_id(), safe='')}&request_uri={quote(request_uri, safe='')}"
    sessions[sid] = {"rid": rid, "jwt": jwt_token, "state": sid, "result": None}
    return sid, deeplink


# ── Verification ─────────────────────────────────────────────

def _untag(o):
    while isinstance(o, cbor2.CBORTag):
        o = o.value
    return o


def _cose_verify(pub, sign1, payload, external_aad=b""):
    """Verify a COSE_Sign1 [protected, unprotected, payload, sig] (ES256, raw r||s)."""
    protected, _unp, _pl, sig = sign1
    if (cbor2.loads(protected) if protected else {}).get(1) not in (-7, -9):
        raise ValueError("unsupported COSE alg")
    to_sign = cbor2.dumps(["Signature1", protected, external_aad, payload])
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, to_sign, ec.ECDSA(hashes.SHA256()))


def _as_dt(v):
    v = _untag(v)
    return v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def verify_document(doc, session, query):
    """Verify one mdoc Document. Returns (fields, verification)."""
    now = datetime.now(timezone.utc)
    v = {"signature": False, "issuer_trusted": False, "not_expired": False,
         "digests_valid": False, "doctype_ok": False, "device_auth": False, "errors": []}
    err = v["errors"].append
    fields = {}

    doctype = doc.get("docType")
    isd = doc.get("issuerSigned", {}) or {}
    wanted = (query.get("meta") or {}).get("doctype_value")
    v["doctype"] = doctype

    # issuerAuth signature with the DSC from x5chain (label 33)
    ia = _untag(isd.get("issuerAuth"))
    try:
        x5 = ia[1].get(33)
        dsc = x509.load_der_x509_certificate(x5 if isinstance(x5, bytes) else x5[0])
        v["issuer"] = dsc.subject.rfc4514_string()
        _cose_verify(dsc.public_key(), ia, ia[2])
        v["signature"] = True
    except Exception as e:
        err(f"issuerAuth signature invalid: {str(e) or type(e).__name__}")
        return fields, v
    mso = _untag(cbor2.loads(_untag(cbor2.loads(ia[2]))))

    # DSC chains to a trusted IACA, and both certificates are in date
    for iaca in trusted_iacas:
        try:
            iaca.public_key().verify(dsc.signature, dsc.tbs_certificate_bytes,
                                     ec.ECDSA(dsc.signature_hash_algorithm))
        except Exception:
            continue
        if not iaca.not_valid_before_utc <= now <= iaca.not_valid_after_utc:
            err(f"trusted IACA out of date: {iaca.subject.rfc4514_string()}")
            break
        v["issuer_trusted"], v["trusted_by"] = True, iaca.subject.rfc4514_string()
        break
    else:
        err("DSC not signed by any trusted IACA")
    if not dsc.not_valid_before_utc <= now <= dsc.not_valid_after_utc:
        v["issuer_trusted"] = False
        err(f"DSC out of date ({dsc.not_valid_before_utc} → {dsc.not_valid_after_utc})")

    # MSO validity window
    vi = mso.get("validityInfo", {})
    try:
        vf, vu = _as_dt(vi["validFrom"]), _as_dt(vi["validUntil"])
        v["valid_until"] = str(vu)
        v["not_expired"] = vf <= now <= vu
        if not v["not_expired"]:
            err(f"MSO outside validity ({vf} → {vu})")
    except Exception as e:
        err(f"bad validityInfo: {e}")

    # docType: Document, MSO and the DCQL query must agree
    v["doctype_ok"] = doctype == mso.get("docType") and (not wanted or doctype == wanted)
    if not v["doctype_ok"]:
        err(f"docType mismatch: document={doctype} mso={mso.get('docType')} requested={wanted}")

    # Element digests (IssuerSignedItemBytes must hash to the MSO valueDigests)
    digests_ok = True
    for ns, items in (isd.get("nameSpaces") or {}).items():
        for item in items:
            el = cbor2.loads(_untag(item))
            ok = mso.get("valueDigests", {}).get(ns, {}).get(el["digestID"]) == \
                hashlib.sha256(cbor2.dumps(item)).digest()
            if not ok:
                digests_ok = False
                err(f"digest mismatch: {ns}/{el.get('elementIdentifier')}")
            val = _untag(el.get("elementValue"))
            fields[el["elementIdentifier"]] = (f"[{len(val)} bytes]" if isinstance(val, bytes)
                                               else str(val) if not isinstance(val, (bool, int, float, str))
                                               else val)
    v["digests_valid"] = digests_ok

    # deviceAuth: DeviceAuthentication over the OID4VP 1.0 SessionTranscript (B.2.6.1)
    try:
        dk = mso["deviceKeyInfo"]["deviceKey"]
        dev_pub = ec.EllipticCurvePublicNumbers(int.from_bytes(dk[-2], "big"), int.from_bytes(dk[-3], "big"),
                                                ec.SECP256R1()).public_key()
        dsd = doc.get("deviceSigned", {}) or {}
        ds = (dsd.get("deviceAuth") or {}).get("deviceSignature")
        if ds is None:
            raise ValueError("no deviceSignature (deviceMac not supported here)")
        info = [client_id(), session["rid"], jwk_thumbprint_bytes(enc_public_jwk()), response_uri()]
        transcript = [None, None, ["OpenID4VPHandover", hashlib.sha256(cbor2.dumps(info)).digest()]]
        dev_auth = ["DeviceAuthentication", transcript, doctype, dsd.get("nameSpaces")]
        dab = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(dev_auth)))    # detached payload
        _cose_verify(dev_pub, _untag(ds), dab)
        v["device_auth"] = True
    except Exception as e:
        err(f"deviceAuth invalid: {str(e) or type(e).__name__}")

    # Claims: report anything returned that the query did not ask for
    asked = {tuple(c["path"])[-1] for c in query.get("claims", [])}
    extra = sorted(set(fields) - asked) if asked else []
    if extra:
        err(f"over-disclosure: returned claims not requested: {extra}")
    return fields, v


def verify_response(payload, session):
    """vp_token is {credential_query_id: [base64url DeviceResponse, ...]} (OID4VP 1.0 §8.1)."""
    queries = {q["id"]: q for q in dcql_query()["credentials"]}
    vp = payload.get("vp_token")
    if not isinstance(vp, dict):
        return {}, {"errors": ["vp_token is not a DCQL object (pre-1.0 wallet?)"]}
    qid = next((k for k in vp if k in queries), None)
    if qid is None:
        return {}, {"errors": [f"vp_token keys {list(vp)} match no DCQL query {list(queries)}"]}
    pres = vp[qid][0] if isinstance(vp[qid], list) else vp[qid]
    dr = cbor2.loads(base64.urlsafe_b64decode(pres + "=" * (-len(pres) % 4)))
    docs = dr.get("documents") or []
    if not docs:
        return {}, {"errors": [f"DeviceResponse has no documents (status {dr.get('status')})"]}
    fields, v = verify_document(docs[0], session, queries[qid])
    v["query_id"] = qid
    return fields, v


def overall(fields, v):
    checks = ("signature", "issuer_trusted", "not_expired", "digests_valid", "doctype_ok", "device_auth")
    return all(v.get(c) for c in checks) and fields.get("age_over_18") is True


# ── Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    sid, deeplink = create_session()
    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data(deeplink)
    qr.make(fit=True)
    buf = BytesIO()
    qr.make_image().save(buf, format="PNG")
    return (PAGE.replace("{{QR}}", base64.b64encode(buf.getvalue()).decode())
            .replace("{{SID}}", sid).replace("{{DEEPLINK}}", html.escape(deeplink)))


@app.route("/v2/presentations/sessions/<sid>/requests/<rid>", methods=["GET", "POST"])
def serve_request(sid, rid):
    s = sessions.get(sid)
    if s and s["rid"] == rid:
        return Response(s["jwt"], content_type="application/oauth-authz-req+jwt")
    return "Not found", 404


@app.route("/v2/presentations/sessions/response", methods=["POST"])
def receive_response():
    raw = request.form.get("response")
    if not raw:
        return jsonify({"error": "invalid_request", "error_description": "missing response"}), 400
    try:
        token = jwe.JWE()
        token.deserialize(raw)
        token.decrypt(enc_key)
        payload = json.loads(token.payload)
    except Exception as e:
        return jsonify({"error": "invalid_request", "error_description": f"cannot decrypt: {e}"}), 400

    session = sessions.get(payload.get("state", ""))
    if not session:
        return jsonify({"error": "invalid_request", "error_description": "unknown state"}), 400
    if session["result"] is not None:
        return jsonify({"error": "invalid_request", "error_description": "response already received"}), 400

    try:
        fields, v = verify_response(payload, session)
    except Exception as e:
        fields, v = {}, {"errors": [f"verification error: {e}"]}
    v["verified"] = overall(fields, v)
    session["result"], session["verification"] = fields, v
    RECENT.append({"ts": datetime.now(timezone.utc).isoformat(), "state": payload.get("state"),
                   "jwe_header": token.jose_header, "fields": fields, "verification": v})
    del RECENT[:-20]

    print(f"\n{'=' * 40}\nRESPONSE {'VERIFIED' if v['verified'] else 'NOT VERIFIED'}")
    for k, val in fields.items():
        print(f"  {k}: {val}")
    for c in ("signature", "issuer_trusted", "not_expired", "digests_valid", "doctype_ok", "device_auth"):
        print(f"  {c:15} {v.get(c)}")
    for e in v.get("errors", []):
        print(f"  [!] {e}")
    print("=" * 40)
    return jsonify({}), 200                      # 1.0 §8.2: 200, optional redirect_uri


@app.route("/status/<sid>")
def status(sid):
    s = sessions.get(sid)
    if not s:
        return jsonify({"status": "unknown"}), 404
    if s["result"] is None:
        return jsonify({"status": "waiting"})
    return jsonify({"status": "received", "fields": s["result"], "verification": s["verification"]})


@app.route("/last")
def last():
    if not RECENT:
        return ("<meta http-equiv=refresh content=3><body style='font-family:sans-serif;padding:40px'>"
                "<h2>No response yet</h2><p>Present a wallet; this page refreshes.</p></body>")
    r = RECENT[-1]
    v = r["verification"]
    ok = v.get("verified")
    rows = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(val))}</td></tr>"
                   for k, val in r["fields"].items())
    checks = "".join(f"<tr><td>{c}</td><td style='color:{'#2e7d32' if v.get(c) else '#c62828'}'>"
                     f"{'✓' if v.get(c) else '✗'}</td></tr>"
                     for c in ("signature", "issuer_trusted", "not_expired", "digests_valid",
                               "doctype_ok", "device_auth"))
    errs = "".join(f"<li>{html.escape(e)}</li>" for e in v.get("errors", []))
    dump = html.escape(json.dumps(r, indent=2, default=str))
    return f"""<!doctype html><meta charset=utf-8><title>Last response</title>
<body style="font-family:-apple-system,system-ui,sans-serif;background:#f5f5f5;padding:30px">
<div style="background:#fff;border-radius:14px;padding:28px;max-width:840px;margin:auto">
<h2 style="color:{'#2e7d32' if ok else '#c62828'}">{'✅ Verified' if ok else '❌ Not verified'}</h2>
<p style="color:#666">{r['ts']} · {len(RECENT)} response(s) since start (newest shown) · <a href="/">verifier home</a></p>
<h3>Claims</h3><table>{rows or '<tr><td>none</td></tr>'}</table>
<h3>Checks</h3><table>{checks}</table>{f'<h3>Errors</h3><ul>{errs}</ul>' if errs else ''}
<h3>Raw</h3><textarea readonly style="width:100%;height:260px;font:11px ui-monospace,monospace">{dump}</textarea>
</div></body>"""


PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Age Verification (OID4VP 1.0)</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #f5f5f5; margin: 0;
         display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: white; border-radius: 16px; padding: 40px; text-align: center;
          box-shadow: 0 4px 24px rgba(0,0,0,0.1); max-width: 440px; width: 90%; }
  .field { background: #f5f5f5; padding: 10px 14px; border-radius: 8px; margin: 6px 0; text-align: left; }
  .ok { color: #2e7d32; font-weight: 600; } .bad { color: #c62828; font-weight: 600; }
  a { color: #1976d2; font-weight: 600; text-decoration: none; }
  #result { display: none; }
</style></head>
<body><div class="card">
  <div id="scan">
    <h1>Age Verification</h1><p style="color:#666">Scan with your wallet (OID4VP 1.0)</p>
    <img src="data:image/png;base64,{{QR}}" style="max-width:300px">
    <p><a href="{{DEEPLINK}}">Open in Wallet</a></p>
    <p style="color:#888">Waiting for response…</p><p><a href="/last">Last response →</a></p>
  </div>
  <div id="result"><div id="mark" style="font-size:3em"></div><h1 id="title"></h1>
    <div id="fields"></div><p><a href="/">Start again</a></p></div>
</div>
<script>
const CHECKS = ["signature","issuer_trusted","not_expired","digests_valid","doctype_ok","device_auth"];
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const poll = setInterval(() => fetch("/status/{{SID}}").then(r => r.json()).then(d => {
  if (d.status !== "received") return;
  clearInterval(poll);
  document.getElementById("scan").style.display = "none";
  document.getElementById("result").style.display = "block";
  const v = d.verification || {};
  document.getElementById("mark").textContent = v.verified ? "\\u2705" : "\\u274C";
  document.getElementById("title").textContent = v.verified ? "Age Verified" : "Verification Failed";
  const f = document.getElementById("fields");
  for (const [k, val] of Object.entries(d.fields || {}))
    f.innerHTML += '<div class="field"><b>' + esc(k) + ':</b> ' + esc(val) + '</div>';
  for (const c of CHECKS)
    f.innerHTML += '<div class="field"><b>' + c + ':</b> <span class="' + (v[c] ? "ok" : "bad") + '">' +
                   (v[c] ? "pass" : "fail") + '</span></div>';
  for (const e of (v.errors || [])) f.innerHTML += '<div class="field bad">' + esc(e) + '</div>';
}).catch(e => console.error("status poll failed:", e)), 2000);
</script></body></html>"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Minimal OID4VP 1.0 verifier")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "verifier_config.json"))
    load_config(ap.parse_args().config)
    print(f"[init] Starting on http://0.0.0.0:{config.get('port', 8080)}")
    app.run(host="0.0.0.0", port=config.get("port", 8080))
