#!/usr/bin/env python3
"""
Minimal ISO 18013-7 / pre-1.0 OID4VP Verifier — WITH Token Status List checking.

Identical to minimal_verifier_18013_7.py (same protocol, checks and pages) plus one addition:
it reads the presented credential's MSO `status.status_list {idx, uri}`, DISPLAYS the status
list URI + index, and performs a live revocation lookup (IETF Token Status List) — fetching the
Status List Token (CWT or JWT), verifying its signature (ES256/384/512; key from an embedded
x5chain/x5c, an embedded JWK, or a did:web kid), and reading the bit at `idx`. The result
becomes a `not_revoked` check.

The status lookup is INLINED (stdlib urllib/ssl/zlib + the crypto already imported) — this file
is self-contained and can be copied to another host on its own; it does NOT import anything from
security_testing/. Credentials with no status pointer are unaffected (the check isn't applied).

It speaks the pre-1.0 OpenID4VP profile used by ISO/IEC 18013-7 (2024) Annex B, which current
production mdoc wallets still implement:

  Request   mdoc-openid4vp:// link with client_id_scheme=x509_san_dns as a separate parameter;
            client_id is the bare DNS name; presentation_definition (not DCQL);
            client_metadata uses vp_formats + authorization_encrypted_response_alg/enc.
            GET /.well-known/oauth-client is served too (some wallets fetch it).
  Response  direct_post.jwt JWE whose header carries apu = base64url(mdoc_generated_nonce);
            vp_token is the base64url DeviceResponse string, with presentation_submission.
  deviceAuth  verified against the ISO 18013-7 OpenID4VP handover:
            SessionTranscript = [null, null, [SHA-256(cbor([client_id, mdoc_nonce])),
                                              SHA-256(cbor([response_uri, mdoc_nonce])),
                                              nonce]]
            (detached COSE_Sign1: external_aad empty, payload = DeviceAuthenticationBytes).

Checks on every presentation: issuerAuth signature, DSC chains to a trusted IACA (trusted_iacas/),
IACA + DSC validity, MSO validFrom/validUntil, docType, element digests, deviceAuth signature
(holder binding + nonce/session binding), returned claims vs the presentation definition.

Wallet makes up to 3 requests:
  1. GET  /v2/presentations/sessions/{sid}/requests/{rid}  — signed request object (JWT)
  2. GET  /.well-known/oauth-client                        — client metadata (optional)
  3. POST /v2/presentations/sessions/response              — encrypted Authorization Response

Usage:
  python minimal_verifier_status.py [--config verifier_config.json]

Config: verifier_config.json (client_id is the bare DNS name). Optional status keys:
  "status_check":    true   — perform the live status lookup (default true)
  "status_insecure": true   — skip TLS verify on the status/did fetch (default true, for test endpoints)
  "status_fail_closed": true — if a status pointer exists but the lookup fails, mark not_revoked false (default true)
Dependencies: pip install flask pyjwt cryptography jwcrypto cbor2 qrcode[pil]
"""

import json, uuid, base64, hashlib, os, glob, argparse, html, zlib, ssl, urllib.request
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

DEFAULT_PD = {"id": "age-verification", "input_descriptors": [{
    "id": "org.iso.23220.photoid.1",
    "format": {"mso_mdoc": {"alg": ["ES256"]}},
    "constraints": {"limit_disclosure": "required", "fields": [
        {"path": ["$['org.iso.23220.1']['age_over_18']"], "intent_to_retain": False}]}}]}


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
    """Pre-1.0 client_id is the bare DNS name; the scheme travels separately as client_id_scheme."""
    return config["client_id"].split(":", 1)[-1]


def response_uri():
    return config["base_url"].rstrip("/") + "/v2/presentations/sessions/response"


def presentation_definition():
    pd = dict(config.get("presentation_definition") or DEFAULT_PD)
    pd["id"] = str(uuid.uuid4())
    return pd


def descriptor_as_query(desc):
    """Turn a presentation_definition input descriptor into {doctype, claims[[ns, element]]} so the
    shared verify_document() can check docType and over-disclosure the same way as with DCQL."""
    claims = []
    for f in (desc.get("constraints") or {}).get("fields", []):
        p = f["path"][0]                               # "$['namespace']['element']"
        ns, el = [x.strip("'\"") for x in p[p.index("[") + 1:-1].split("][")]
        claims.append({"path": [ns, el]})
    return {"id": desc["id"], "meta": {"doctype_value": desc["id"]}, "claims": claims}


def kid():
    return base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).rstrip(b"=").decode()


def enc_public_jwk():
    return json.loads(enc_key.export_public())


# ── Request ──────────────────────────────────────────────────

def create_session():
    sid, rid = str(uuid.uuid4()), str(uuid.uuid4())
    payload = {
        "aud": "https://self-issued.me/v2",
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "client_id": client_id(),
        "client_id_scheme": "x509_san_dns",
        "response_uri": response_uri(),
        "nonce": rid,
        "state": sid,
        "presentation_definition": presentation_definition(),
        "client_metadata": {
            "jwks": {"keys": [enc_public_jwk()]},
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "require_signed_request_object": True,
        },
    }
    jwt_token = pyjwt.encode(payload, signing_key, algorithm="ES256",
                             headers={"typ": "oauth-authz-req+jwt", "kid": kid(),
                                      "x5c": [base64.b64encode(cert_der).decode()]})
    request_uri = f"{config['base_url']}/v2/presentations/sessions/{sid}/requests/{rid}"
    scheme = config.get("wallet_scheme", "mdoc-openid4vp://")
    deeplink = (f"{scheme}?client_id={quote(client_id(), safe='')}"
                f"&request_uri={quote(request_uri, safe='')}&client_id_scheme=x509_san_dns")
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


# ── Token Status List lookup (self-contained; IETF draft-ietf-oauth-status-list) ──
# Reads status.status_list {idx, uri}: fetches the Status List Token (CWT or JWT),
# verifies its signature (ES256/384/512) against a key from an embedded x5chain/x5c,
# an embedded JWK, or a did:web kid, then reads the bit at idx. stdlib-only networking.

_SL_LABELS = {0: "VALID", 1: "INVALID", 2: "SUSPENDED", 3: "APPLICATION_SPECIFIC"}
_SL_COSE_ALG = {-7: "ES256", -35: "ES384", -36: "ES512"}
_SL_HASH = {"ES256": hashes.SHA256, "ES384": hashes.SHA384, "ES512": hashes.SHA512}
_SL_CRV = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}


def _sl_label(val):
    if val in _SL_LABELS:
        return _SL_LABELS[val]
    return f"APPLICATION_SPECIFIC(0x{val:02x})" if 0x0B <= val <= 0x0F else f"UNKNOWN(0x{val:02x})"


def _sl_b64url(s):
    if isinstance(s, (bytes, bytearray)):
        s = s.decode("ascii")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sl_fetch(uri, insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(uri, headers={
        "Accept": "application/statuslist+jwt, application/statuslist+cwt, application/json"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return resp.read(), resp.headers.get("Content-Type", "")


def _sl_inflate(data):
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):  # zlib / raw / gzip
        try:
            return zlib.decompress(data, wbits)
        except Exception:  # noqa: BLE001
            continue
    raise ValueError("could not decompress status list")


def _sl_read_index(lst, bits, idx):
    bit_pos = idx * bits
    byte_i, shift = bit_pos // 8, bit_pos % 8
    if byte_i >= len(lst):
        raise IndexError(f"idx {idx} past end ({byte_i} >= {len(lst)} bytes)")
    return (lst[byte_i] >> shift) & ((1 << bits) - 1)


def _sl_pubkey_from_jwk(j):
    crv = _SL_CRV.get(j.get("crv"))
    if crv is None:
        raise ValueError(f"unsupported JWK crv {j.get('crv')}")
    x = int.from_bytes(_sl_b64url(j["x"]), "big")
    y = int.from_bytes(_sl_b64url(j["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, crv()).public_key()


def _sl_resolve_did_web(kid, insecure):
    did = kid.split("#")[0]
    parts = did.split(":")
    if len(parts) < 3 or parts[1] != "web":
        raise ValueError("not a did:web kid")
    host, segs = parts[2].replace("%3A", ":"), parts[3:]
    url = ("https://" + host + "/" + "/".join(segs) + "/did.json") if segs \
        else f"https://{host}/.well-known/did.json"
    body, _ = _sl_fetch(url, insecure)
    doc = json.loads(body)
    vms = doc.get("verificationMethod", []) or []
    frag = kid.split("#")[-1]
    vm = (next((x for x in vms if x.get("id") == kid), None)
          or next((x for x in vms if str(x.get("id", "")).split("#")[-1] == frag), None)
          or (vms[0] if vms else None))
    if vm and vm.get("publicKeyJwk"):
        return _sl_pubkey_from_jwk(vm["publicKeyJwk"]), f"did:web ({url})"
    raise ValueError("no usable verificationMethod in did document")


def _sl_ecdsa_verify(pub, alg, signing_input, raw_sig):
    n = len(raw_sig) // 2
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature as _enc
    der = _enc(int.from_bytes(raw_sig[:n], "big"), int.from_bytes(raw_sig[n:], "big"))
    pub.verify(der, signing_input, ec.ECDSA(_SL_HASH[alg]()))


def _sl_cert_pubkey(x5):
    der = x5[0] if isinstance(x5, list) else x5
    cert = x509.load_der_x509_certificate(bytes(der))
    return cert.public_key(), f"x5chain ({cert.subject.rfc4514_string()})"


def _sl_verify(candidates, alg, signing_input, raw_sig, out):
    tried = []
    for get_key in candidates:
        try:
            pub, method = get_key()
        except Exception as e:  # noqa: BLE001
            tried.append(str(e))
            continue
        try:
            _sl_ecdsa_verify(pub, alg, signing_input, raw_sig)
            out["signature"] = {"verified": True, "method": method}
            return
        except Exception as e:  # noqa: BLE001
            tried.append(f"{method}: {str(e) or type(e).__name__}")
    out["signature"] = {"verified": False if tried else None,
                        "method": None, "note": "; ".join(tried) or "no verifying key"}


def _sl_lookup(uri, idx, insecure=True):
    """Fetch+read a Status List Token. Returns {status_label,status_value,signature,errors,bits}."""
    out = {"status_label": None, "status_value": None, "bits": None,
           "signature": {"verified": None, "method": None}, "errors": []}
    try:
        raw, ct = _sl_fetch(uri, insecure)
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"fetch failed: {e}")
        return out
    ct = (ct or "").lower()
    text = None
    try:
        text = raw.decode("utf-8").strip()
    except Exception:  # noqa: BLE001
        pass

    # plain-JSON stub
    if ("json" in ct and "statuslist" not in ct) or (text and text[:1] == "{" and "statuslist" not in ct):
        try:
            doc = json.loads(text)
            rev, susp = doc.get("revoked"), doc.get("suspended")
            out["status_value"] = 1 if rev else 2 if susp else 0
            out["status_label"] = _sl_label(out["status_value"])
            out["signature"]["note"] = "plain JSON — unsigned, spoofable"
            return out
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"JSON parse failed: {e}")
            return out

    is_jwt = ("jwt" in ct) or (text is not None and text.count(".") == 2 and " " not in text)
    try:
        if is_jwt:
            h_b64, p_b64, s_b64 = text.split(".")
            hdr, claims = json.loads(_sl_b64url(h_b64)), json.loads(_sl_b64url(p_b64))
            alg = hdr.get("alg")
            signing_input, raw_sig = (h_b64 + "." + p_b64).encode(), _sl_b64url(s_b64)
            sl = claims.get("status_list") or {}
            kid = hdr.get("kid") or claims.get("iss")
            cands = []
            if hdr.get("x5c"):
                cands.append(lambda: _sl_cert_pubkey([base64.b64decode(hdr["x5c"][0])]))
            if isinstance(hdr.get("jwk"), dict):
                cands.append(lambda: (_sl_pubkey_from_jwk(hdr["jwk"]), "jwk header"))
            if isinstance(kid, str) and kid.startswith("did:web:"):
                cands.append(lambda: _sl_resolve_did_web(kid, insecure))
        else:
            obj = cbor2.loads(raw)
            while isinstance(obj, cbor2.CBORTag):
                tag, obj = obj.tag, obj.value
                if tag == 18:
                    break
            prot, unprot, payload_bstr, sig = obj
            unprot = dict(unprot) if hasattr(unprot, "items") else {}   # cbor2 may give a FrozenDict
            phdr = cbor2.loads(prot) if prot else {}
            alg = _SL_COSE_ALG.get(phdr.get(1))
            claims = cbor2.loads(payload_bstr)
            if isinstance(claims, cbor2.CBORTag):
                claims = claims.value
            sl = claims.get(65533) or claims.get("status_list") or {}
            signing_input, raw_sig = cbor2.dumps(["Signature1", prot, b"", payload_bstr]), sig
            kid = None
            for hd in (unprot or {}, phdr or {}):
                if isinstance(hd, dict) and hd.get(4) is not None:
                    kid = hd[4].decode() if isinstance(hd[4], (bytes, bytearray)) else hd[4]
                    break
            cands = []
            for hd in (phdr or {}, unprot or {}):
                x5 = hd.get(33) if isinstance(hd, dict) else None
                if x5:
                    cands.append(lambda x5=x5: _sl_cert_pubkey(x5))
            if isinstance(kid, str) and kid.startswith("did:web:"):
                cands.append(lambda: _sl_resolve_did_web(kid, insecure))
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"token parse failed: {e}")
        return out

    bits, lst_enc = (sl.get("bits") or sl.get(0)), (sl.get("lst") or sl.get(1))
    if not bits or lst_enc is None:
        out["errors"].append("no status_list claim in token")
        return out
    out["bits"] = bits
    if alg not in _SL_HASH:
        out["errors"].append(f"unsupported signature alg {alg!r}")
        out["signature"] = {"verified": None, "method": None, "note": f"alg {alg}"}
    else:
        _sl_verify(cands, alg, signing_input, raw_sig, out)
    try:
        lst = _sl_inflate(_sl_b64url(lst_enc) if isinstance(lst_enc, str) else lst_enc)
        val = _sl_read_index(lst, bits, idx)
        out["status_value"], out["status_label"] = val, _sl_label(val)
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"status read failed: {e}")
    return out


def _check_status(mso, v):
    """Read MSO status.status_list {idx, uri}, display it, and look it up (revocation).

    Sets on v: status_present, status_uri, status_idx, identifier_list_uri,
    status_label, status_value, status_sig_verified/method, and the not_revoked check.
    """
    status = mso.get("status") if isinstance(mso, dict) else None
    sl = status.get("status_list") if isinstance(status, dict) else None
    if isinstance(status, dict) and isinstance(status.get("identifier_list"), dict):
        v["identifier_list_uri"] = status["identifier_list"].get("uri")
    if not isinstance(sl, dict) or not sl.get("uri") or sl.get("idx") is None:
        v["status_present"] = False
        return
    v["status_present"] = True
    v["status_uri"], v["status_idx"] = sl["uri"], sl["idx"]

    fail_closed = config.get("status_fail_closed", True)
    if not config.get("status_check", True):
        v["errors"].append("status pointer present but status_check is disabled in config")
        return

    try:
        r = _sl_lookup(sl["uri"], sl["idx"], insecure=config.get("status_insecure", True))
    except Exception as e:  # noqa: BLE001
        v["errors"].append(f"status lookup error: {e}")
        if fail_closed:
            v["not_revoked"] = False
        return

    v["status_label"] = r.get("status_label")
    v["status_value"] = r.get("status_value")
    sig = r.get("signature") or {}
    v["status_sig_verified"] = sig.get("verified")
    v["status_sig_method"] = sig.get("method")

    if r.get("status_value") == 0:
        v["not_revoked"] = True
    elif r.get("status_value") is not None:
        v["not_revoked"] = False
        v["errors"].append(f"credential status is {r.get('status_label')} (idx {sl['idx']})")
    else:
        v["errors"].append("status could not be determined: " + "; ".join(r.get("errors", [])))
        v["not_revoked"] = not fail_closed

    # A status list we cannot authenticate must not be trusted.
    if v.get("status_sig_verified") is False:
        v["not_revoked"] = False
        v["errors"].append("status list token signature INVALID")
    elif v.get("status_sig_verified") is None:
        v["errors"].append("status list token signature not verified (no anchored key)")


def verify_document(doc, session, query, mdoc_nonce):
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

    # docType: Document, MSO and the requested docType must agree
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

    # deviceAuth: DeviceAuthentication over the ISO 18013-7 OpenID4VP SessionTranscript
    try:
        dk = mso["deviceKeyInfo"]["deviceKey"]
        dev_pub = ec.EllipticCurvePublicNumbers(int.from_bytes(dk[-2], "big"), int.from_bytes(dk[-3], "big"),
                                                ec.SECP256R1()).public_key()
        dsd = doc.get("deviceSigned", {}) or {}
        ds = (dsd.get("deviceAuth") or {}).get("deviceSignature")
        if ds is None:
            raise ValueError("no deviceSignature (deviceMac not supported here)")
        if not mdoc_nonce:
            raise ValueError("no mdoc_generated_nonce (JWE apu header missing)")
        H = lambda v: hashlib.sha256(cbor2.dumps(v)).digest()
        transcript = [None, None, [H([client_id(), mdoc_nonce]), H([response_uri(), mdoc_nonce]),
                                   session["rid"]]]
        dev_auth = ["DeviceAuthentication", transcript, doctype, dsd.get("nameSpaces")]
        dab = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(dev_auth)))    # detached payload
        _cose_verify(dev_pub, _untag(ds), dab)
        v["device_auth"] = True
    except Exception as e:
        err(f"deviceAuth invalid: {str(e) or type(e).__name__}")

    # Token Status List (revocation): read + display status.status_list, look it up
    try:
        _check_status(mso, v)
    except Exception as e:  # noqa: BLE001
        err(f"status check error: {e}")

    # Claims: report anything returned that the query did not ask for
    asked = {tuple(c["path"])[-1] for c in query.get("claims", [])}
    extra = sorted(set(fields) - asked) if asked else []
    if extra:
        err(f"over-disclosure: returned claims not requested: {extra}")
    return fields, v


def verify_response(payload, session, mdoc_nonce):
    """vp_token is the base64url DeviceResponse string (pre-1.0), described by presentation_submission."""
    desc = (config.get("presentation_definition") or DEFAULT_PD)["input_descriptors"][0]
    pres = payload.get("vp_token")
    if not isinstance(pres, str):
        return {}, {"errors": ["vp_token is not a DeviceResponse string (OID4VP 1.0 wallet? "
                               "use minimal_verifier_1_0.py)"]}
    dr = cbor2.loads(base64.urlsafe_b64decode(pres + "=" * (-len(pres) % 4)))
    docs = dr.get("documents") or []
    if not docs:
        return {}, {"errors": [f"DeviceResponse has no documents (status {dr.get('status')})"]}
    fields, v = verify_document(docs[0], session, descriptor_as_query(desc), mdoc_nonce)
    v["descriptor_id"] = desc["id"]
    return fields, v


def overall(fields, v):
    checks = ["signature", "issuer_trusted", "not_expired", "digests_valid", "doctype_ok", "device_auth"]
    if v.get("status_present"):
        checks.append("not_revoked")        # only gates verification when the credential carries a status
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

    apu = (token.jose_header or {}).get("apu")
    try:
        mdoc_nonce = base64.urlsafe_b64decode(apu + "=" * (-len(apu) % 4)).decode() if apu else None
    except Exception:
        mdoc_nonce = None
    try:
        fields, v = verify_response(payload, session, mdoc_nonce)
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
    if v.get("status_present"):
        print(f"  {'not_revoked':15} {v.get('not_revoked')}")
        print(f"  status_list.uri: {v.get('status_uri')}")
        print(f"  status_list.idx: {v.get('status_idx')}  -> {v.get('status_label')}"
              f"  (sig: {v.get('status_sig_verified')} via {v.get('status_sig_method')})")
    elif "status_present" in v:
        print("  status:          (credential carries no status_list pointer)")
    if v.get("identifier_list_uri"):
        print(f"  identifier_list: {v.get('identifier_list_uri')}")
    for e in v.get("errors", []):
        print(f"  [!] {e}")
    print("=" * 40)
    return jsonify({}), 200                      # 1.0 §8.2: 200, optional redirect_uri


@app.route("/.well-known/oauth-client")
def oauth_client():
    """Pre-1.0 client metadata endpoint; some wallets fetch it before responding."""
    n = x509.load_der_x509_certificate(cert_der).public_key().public_numbers()
    b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()
    return jsonify({
        "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y),
                           "use": "sig", "alg": "ES256", "kid": kid()}]},
        "authorization_encrypted_response_alg": "ECDH-ES",
        "authorization_encrypted_response_enc": "A256GCM",
        "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        "require_signed_request_object": True})


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
    check_names = ["signature", "issuer_trusted", "not_expired", "digests_valid", "doctype_ok", "device_auth"]
    if v.get("status_present"):
        check_names.append("not_revoked")
    checks = "".join(f"<tr><td>{c}</td><td style='color:{'#2e7d32' if v.get(c) else '#c62828'}'>"
                     f"{'✓' if v.get(c) else '✗'}</td></tr>" for c in check_names)
    if v.get("status_present"):
        sig_v = v.get("status_sig_verified")
        sig_txt = {True: "✓ verified", False: "✗ INVALID", None: "not verified"}.get(sig_v, str(sig_v))
        status_html = (f"<h3>Credential status (Token Status List)</h3><table>"
                       f"<tr><td>status</td><td>{html.escape(str(v.get('status_label')))}</td></tr>"
                       f"<tr><td>idx</td><td>{html.escape(str(v.get('status_idx')))}</td></tr>"
                       f"<tr><td>uri</td><td style='word-break:break-all'>{html.escape(str(v.get('status_uri')))}</td></tr>"
                       f"<tr><td>token signature</td><td>{sig_txt}"
                       f" {html.escape(str(v.get('status_sig_method') or ''))}</td></tr></table>")
    elif "status_present" in v:
        status_html = "<h3>Credential status</h3><p style='color:#666'>No status_list pointer in this credential.</p>"
    else:
        status_html = ""
    errs = "".join(f"<li>{html.escape(e)}</li>" for e in v.get("errors", []))
    dump = html.escape(json.dumps(r, indent=2, default=str))
    return f"""<!doctype html><meta charset=utf-8><title>Last response</title>
<body style="font-family:-apple-system,system-ui,sans-serif;background:#f5f5f5;padding:30px">
<div style="background:#fff;border-radius:14px;padding:28px;max-width:840px;margin:auto">
<h2 style="color:{'#2e7d32' if ok else '#c62828'}">{'✅ Verified' if ok else '❌ Not verified'}</h2>
<p style="color:#666">{r['ts']} · {len(RECENT)} response(s) since start (newest shown) · <a href="/">verifier home</a></p>
<h3>Claims</h3><table>{rows or '<tr><td>none</td></tr>'}</table>
<h3>Checks</h3><table>{checks}</table>{status_html}{f'<h3>Errors</h3><ul>{errs}</ul>' if errs else ''}
<h3>Raw</h3><textarea readonly style="width:100%;height:260px;font:11px ui-monospace,monospace">{dump}</textarea>
</div></body>"""


PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Age Verification (ISO 18013-7)</title>
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
    <h1>Age Verification</h1><p style="color:#666">Scan with your wallet (ISO 18013-7)</p>
    <img src="data:image/png;base64,{{QR}}" style="max-width:300px">
    <p><a href="{{DEEPLINK}}">Open in Wallet</a></p>
    <p style="color:#888">Waiting for response…</p><p><a href="/last">Last response →</a></p>
  </div>
  <div id="result"><div id="mark" style="font-size:3em"></div><h1 id="title"></h1>
    <div id="fields"></div><p><a href="/">Start again</a></p></div>
</div>
<script>
const CHECKS = ["signature","issuer_trusted","not_expired","digests_valid","doctype_ok","device_auth","not_revoked"];
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
  for (const c of CHECKS) {
    if (v[c] === undefined) continue;    // not_revoked only present when the credential carries a status
    f.innerHTML += '<div class="field"><b>' + c + ':</b> <span class="' + (v[c] ? "ok" : "bad") + '">' +
                   (v[c] ? "pass" : "fail") + '</span></div>';
  }
  if (v.status_present) {
    const sig = {true:"\\u2713 verified", false:"\\u2717 INVALID"}[v.status_sig_verified] || "not verified";
    f.innerHTML += '<div class="field"><b>status:</b> ' + esc(v.status_label) + ' (idx ' + esc(v.status_idx) +
                   ', token sig: ' + sig + ')</div>';
    f.innerHTML += '<div class="field" style="word-break:break-all"><b>status uri:</b> ' + esc(v.status_uri) + '</div>';
  } else if ("status_present" in v) {
    f.innerHTML += '<div class="field"><b>status:</b> no status_list pointer</div>';
  }
  for (const e of (v.errors || [])) f.innerHTML += '<div class="field bad">' + esc(e) + '</div>';
}).catch(e => console.error("status poll failed:", e)), 2000);
</script></body></html>"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Minimal ISO 18013-7 verifier WITH Token Status List checking")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "verifier_config.json"))
    load_config(ap.parse_args().config)
    print(f"[init] Starting on http://0.0.0.0:{config.get('port', 8080)}")
    app.run(host="0.0.0.0", port=config.get("port", 8080))
