#!/usr/bin/env python3
"""
Minimal Wallet — single-file ISO mdoc wallet.

The holder-side counterpart of minimal_issuer/ and minimal_verifier/minimal_verifier_1_0.py:
  issue    OID4VCI 1.0, pre-authorized code flow only (no tx_code, no auth-code flow)
  present  OID4VP 1.0, DCQL + mso_mdoc, signed request (x509_san_dns / x509_hash),
           direct_post.jwt (or direct_post), deviceAuth over the OpenID4VPHandover transcript
  list     stored credentials

Storage (default ./store next to this file, override with --store):
  device_key.pem   one P-256 device key, generated on first use, bound into every credential
  creds/*.cbor     IssuerSigned structures exactly as issued
  trusted_verifiers/  root certs (PEM/DER) for verifier request signing. If a request's x5c
                      chains to one, any response_uri is allowed; otherwise the response_uri
                      host must equal the x509_san_dns name.

Usage:
  python minimal_wallet.py issue   'openid-credential-offer://?credential_offer_uri=...'
  python minimal_wallet.py present 'openid4vp://?client_id=...&request_uri=...' [--yes]
  python minimal_wallet.py list
  python minimal_wallet.py --client-id my-wallet issue    # issuers that require iss in the proof

  Omit the link to be prompted for it (paste it there; no shell quoting needed).

Dependencies: pip install cryptography cbor2 pyjwt jwcrypto
"""

import argparse, base64, datetime, glob, hashlib, json, os, ssl, sys, time
import urllib.parse, urllib.request
from urllib.error import HTTPError

import cbor2
import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from jwcrypto import jwe, jwk

PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "store")
TLS = ssl.create_default_context()          # certificates are always verified


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def untag(o):
    while isinstance(o, cbor2.CBORTag):
        o = o.value
    return o


def http(method, url, form=None, json_body=None, headers=None):
    """Return (status, body_bytes, content_type). Never raises on HTTP errors."""
    data, hdrs = None, dict(headers or {})
    if form is not None:
        data, hdrs["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    elif json_body is not None:
        data, hdrs["Content-Type"] = json.dumps(json_body).encode(), "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "")


def http_json(method, url, **kw):
    st, body, _ = http(method, url, **kw)
    if st >= 400:
        sys.exit(f"❌ {method} {url} → HTTP {st}: {body[:300].decode(errors='replace')}")
    return json.loads(body) if body else {}


def well_known(base, suffix):
    """RFC 8414-style: insert /.well-known/<suffix> between host and path."""
    u = urllib.parse.urlparse(base)
    return f"{u.scheme}://{u.netloc}/.well-known/{suffix}{u.path.rstrip('/')}"


# ── Device key + storage ─────────────────────────────────────

def device_key():
    path = os.path.join(STORE, "device_key.pem")
    if not os.path.exists(path):
        os.makedirs(STORE, exist_ok=True)
        k = ec.generate_private_key(ec.SECP256R1())
        with open(path, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        print(f"🔑 Generated device key {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def mso_of(issuer_signed):
    return untag(cbor2.loads(untag(cbor2.loads(issuer_signed["issuerAuth"][2]))))


def _when(v):
    v = untag(v)
    return v if isinstance(v, datetime.datetime) else \
        datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def stored_credentials():
    """All stored credentials, newest first (by the MSO's validityInfo.signed)."""
    creds = []
    for path in glob.glob(os.path.join(STORE, "creds", "*.cbor")):
        with open(path, "rb") as f:
            isd = cbor2.loads(f.read())
        creds.append((path, isd, mso_of(isd)))
    return sorted(creds, key=lambda c: (_when(c[2]["validityInfo"]["signed"]), c[0]), reverse=True)


def issuer_of(isd):
    """Subject of the document signer certificate (x5chain, label 33)."""
    x5 = isd["issuerAuth"][1].get(33)
    return x509.load_der_x509_certificate(x5 if isinstance(x5, bytes) else x5[0]).subject.rfc4514_string()


def validity_label(mso):
    vi, now = mso["validityInfo"], datetime.datetime.now(datetime.timezone.utc)
    vf, vu = _when(vi["validFrom"]), _when(vi["validUntil"])
    state = "EXPIRED" if now > vu else "NOT YET VALID" if now < vf else "valid"
    return f"{state}, until {vu:%Y-%m-%d}"


def element_names(isd):
    return {ns: {cbor2.loads(untag(i))["elementIdentifier"] for i in items}
            for ns, items in isd["nameSpaces"].items()}


# ── issue (OID4VCI 1.0, pre-authorized code) ─────────────────

def issue(link, client_id=None):
    """client_id: optional. Sent to the token endpoint and used as the proof's iss. Without it the
    flow is anonymous pre-auth, where OID4VCI 1.0 Appendix F.1 says iss MUST be omitted. Some
    issuers reject a proof without iss, so pass --client-id for those."""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
    if "credential_offer_uri" in q:
        offer = http_json("GET", q["credential_offer_uri"][0])
    elif "credential_offer" in q:
        offer = json.loads(q["credential_offer"][0])
    else:
        sys.exit("❌ Not a credential offer link")
    grant = (offer.get("grants") or {}).get(PRE_AUTH)
    if not grant:
        sys.exit("❌ Offer has no pre-authorized code grant (only pre-auth is supported)")
    if grant.get("tx_code"):
        sys.exit("❌ Offer requires a transaction code (not supported)")

    issuer = offer["credential_issuer"]
    cfg_id = offer["credential_configuration_ids"][0]
    meta = http_json("GET", well_known(issuer, "openid-credential-issuer"))
    cfg = meta["credential_configurations_supported"][cfg_id]
    if cfg.get("format") != "mso_mdoc":
        sys.exit(f"❌ Only mso_mdoc is supported (offer is {cfg.get('format')})")
    as_url = (meta.get("authorization_servers") or [issuer])[0]
    as_meta = http_json("GET", well_known(as_url, "oauth-authorization-server"))
    print(f"📥 {issuer} offers {cfg.get('doctype')} ('{cfg_id}')")

    form = {"grant_type": PRE_AUTH, "pre-authorized_code": grant["pre-authorized_code"]}
    if client_id:
        form["client_id"] = client_id
    tok = http_json("POST", as_meta["token_endpoint"], form=form)
    nonce = http_json("POST", meta["nonce_endpoint"])["c_nonce"] if meta.get("nonce_endpoint") else None

    key = device_key()
    claims = {"aud": issuer, "iat": int(time.time())}
    if nonce:
        claims["nonce"] = nonce
    if client_id:
        claims["iss"] = client_id
    proof = pyjwt.encode(claims, key, algorithm="ES256",
                         headers={"typ": "openid4vci-proof+jwt", "jwk": public_jwk(key)})
    resp = http_json("POST", meta["credential_endpoint"],
                     json_body={"credential_configuration_id": cfg_id, "proofs": {"jwt": [proof]}},
                     headers={"Authorization": f"{tok.get('token_type', 'Bearer')} {tok['access_token']}"})
    if "credentials" not in resp:
        sys.exit(f"❌ No credential returned (deferred issuance is not supported): {resp}")

    raw = b64u_dec(resp["credentials"][0]["credential"])
    isd = cbor2.loads(raw)
    mso = mso_of(isd)
    dk = mso["deviceKeyInfo"]["deviceKey"]
    if b64u(dk[-2]) != public_jwk(key)["x"]:
        sys.exit("❌ Issued credential is not bound to this wallet's device key")
    os.makedirs(os.path.join(STORE, "creds"), exist_ok=True)
    stem = os.path.join(STORE, "creds", f"{mso['docType']}-{datetime.datetime.now():%Y%m%d-%H%M%S}")
    path, n = f"{stem}.cbor", 1
    while os.path.exists(path):                  # never overwrite (two issuances in one second)
        n += 1
        path = f"{stem}-{n}.cbor"
    with open(path, "wb") as f:
        f.write(raw)
    print(f"✅ Saved {path} — {sum(map(len, element_names(isd).values()))} elements, "
          f"valid until {untag(mso['validityInfo']['validUntil'])}")


# ── present (OID4VP 1.0) ─────────────────────────────────────

def trusted_roots():
    roots = []
    for p in glob.glob(os.path.join(STORE, "trusted_verifiers", "*")):
        data = open(p, "rb").read()
        roots.append(x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data
                     else x509.load_der_x509_certificate(data))
    return roots


def signed_by(cert, issuer_cert):
    try:
        issuer_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                        ec.ECDSA(cert.signature_hash_algorithm))
        return cert.issuer == issuer_cert.subject
    except Exception:
        return False


def chain_trusted(chain):
    """x5c chain (leaf first) is internally consistent, in date, and ends at a trusted root."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if any(not c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in chain):
        return False
    if any(not signed_by(chain[i], chain[i + 1]) for i in range(len(chain) - 1)):
        return False
    return any(chain[-1] == r or signed_by(chain[-1], r) for r in trusted_roots())


def fetch_request(link):
    q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(link).query).items()}
    if "request_uri" in q:
        method = "POST" if q.get("request_uri_method") == "post" else "GET"
        st, body, _ = http(method, q["request_uri"], form={} if method == "POST" else None)
        if st != 200:
            sys.exit(f"❌ request_uri → HTTP {st}")
        jws = body.decode().strip()
    elif "request" in q:
        jws = q["request"]
    else:
        sys.exit("❌ Only signed requests (request / request_uri) are supported")

    hdr = pyjwt.get_unverified_header(jws)
    if hdr.get("typ") != "oauth-authz-req+jwt" or not hdr.get("x5c"):
        sys.exit("❌ Request object must be typ oauth-authz-req+jwt with an x5c header")
    chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in hdr["x5c"]]
    leaf = chain[0]
    try:
        req = pyjwt.decode(jws, leaf.public_key(), algorithms=["ES256"], options={"verify_aud": False})
    except pyjwt.InvalidTokenError as e:
        sys.exit(f"❌ Request object signature invalid: {e}")
    if q.get("client_id") and q["client_id"] != req.get("client_id"):
        sys.exit("❌ client_id in the link differs from the signed request")

    cid = req["client_id"]
    prefix, _, value = cid.partition(":")
    if prefix == "x509_san_dns":
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if value not in sans.get_values_for_type(x509.DNSName):
            sys.exit(f"❌ {value} is not a dNSName SAN of the request signing certificate")
    elif prefix == "x509_hash":
        if b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()) != value:
            sys.exit("❌ x509_hash does not match the request signing certificate")
    else:
        sys.exit(f"❌ Unsupported client identifier prefix: {prefix or '(none)'}")

    trusted = chain_trusted(chain)
    host = urllib.parse.urlparse(req.get("response_uri", "")).hostname
    if not trusted:
        if prefix != "x509_san_dns" or host != value:
            sys.exit(f"❌ Verifier certificate is not trusted and response_uri host {host} "
                     f"is not the client identifier — refusing (add its root to trusted_verifiers/)")
        print("⚠️  Verifier certificate chain is not in trusted_verifiers/ — "
              f"proceeding only because response_uri host matches {value}")
    return req, trusted


def find_credential(query, assume_yes=False):
    """Credentials matching the DCQL query (docType + every requested element), newest first.
    One match is used directly; with several the user picks (Enter / --yes = newest).
    Expired or not-yet-valid credentials are offered too — they are labelled, not skipped."""
    doctype = (query.get("meta") or {}).get("doctype_value")
    wanted = [tuple(c["path"]) for c in query.get("claims", [])]
    matches = [(path, isd, mso) for path, isd, mso in stored_credentials()
               if mso["docType"] == doctype
               and all(p[1] in element_names(isd).get(p[0], ()) for p in wanted)]
    if not matches:
        sys.exit(f"❌ No stored {doctype} credential has {[p[1] for p in wanted]}")
    if len(matches) > 1 and not assume_yes:
        print(f"🗂  {len(matches)} credentials match:")
        for i, (path, isd, mso) in enumerate(matches, 1):
            print(f"   [{i}] {os.path.basename(path)}\n       issuer: {issuer_of(isd)}"
                  f"\n       {validity_label(mso)}")
        choice = input(f"   Choose 1-{len(matches)} (Enter = 1, newest): ").strip() or "1"
        if not choice.isdigit() or not 1 <= int(choice) <= len(matches):
            sys.exit("❌ Invalid choice")
        path, isd, mso = matches[int(choice) - 1]
    else:
        path, isd, mso = matches[0]
    return path, isd, mso, wanted


def device_response(isd, mso, wanted, transcript, key):
    """DeviceResponse with only the requested elements and a deviceSignature over the transcript."""
    keep = {}
    for ns, items in isd["nameSpaces"].items():
        sel = [i for i in items if (ns, cbor2.loads(untag(i))["elementIdentifier"]) in wanted]
        if sel:
            keep[ns] = sel
    dev_ns = cbor2.CBORTag(24, cbor2.dumps({}))
    dab = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(
        ["DeviceAuthentication", transcript, mso["docType"], dev_ns])))
    protected = cbor2.dumps({1: -7})
    r, s = decode_dss_signature(key.sign(cbor2.dumps(["Signature1", protected, b"", dab]),
                                         ec.ECDSA(hashes.SHA256())))
    sign1 = [protected, {}, None, r.to_bytes(32, "big") + s.to_bytes(32, "big")]   # detached payload
    doc = {"docType": mso["docType"],
           "issuerSigned": {"nameSpaces": keep, "issuerAuth": isd["issuerAuth"]},
           "deviceSigned": {"nameSpaces": dev_ns, "deviceAuth": {"deviceSignature": sign1}}}
    return cbor2.dumps({"version": "1.0", "documents": [doc], "status": 0})


def present(link, assume_yes=False):
    req, trusted = fetch_request(link)
    mode = req.get("response_mode")
    if mode not in ("direct_post", "direct_post.jwt"):
        sys.exit(f"❌ response_mode {mode} not supported")
    query = req["dcql_query"]["credentials"][0]
    if query.get("format") != "mso_mdoc":
        sys.exit("❌ Only mso_mdoc DCQL queries are supported")
    path, isd, mso, wanted = find_credential(query, assume_yes)

    print(f"📤 {req['client_id']} {'(trusted)' if trusted else ''} requests from {mso['docType']}:")
    for ns, name in wanted:
        print(f"     {ns} / {name}")
    print(f"   using {os.path.basename(path)} ({validity_label(mso)})\n"
          f"   issuer {issuer_of(isd)}\n   response to {req['response_uri']}")
    if not assume_yes and input("   Share? [y/N] ").strip().lower() != "y":
        sys.exit("Declined.")

    enc = None
    if mode == "direct_post.jwt":
        md = req.get("client_metadata") or {}
        enc = next((k for k in (md.get("jwks") or {}).get("keys", [])
                    if k.get("kty") == "EC" and k.get("crv") == "P-256" and k.get("alg") == "ECDH-ES"), None)
        if not enc:
            sys.exit("❌ No ECDH-ES P-256 key in client_metadata.jwks")
    thumb = (hashlib.sha256(json.dumps({m: enc[m] for m in ("crv", "kty", "x", "y")},
                                       separators=(",", ":"), sort_keys=True).encode()).digest()
             if enc else None)
    info = [req["client_id"], req["nonce"], thumb, req["response_uri"]]
    transcript = [None, None, ["OpenID4VPHandover", hashlib.sha256(cbor2.dumps(info)).digest()]]

    payload = {"vp_token": {query["id"]: [b64u(device_response(isd, mso, wanted, transcript, device_key()))]}}
    if "state" in req:
        payload["state"] = req["state"]

    if enc:
        enc_alg = next((e for e in (req["client_metadata"].get("encrypted_response_enc_values_supported")
                                    or ["A128GCM"]) if e in ("A128GCM", "A256GCM")), None)
        if not enc_alg:
            sys.exit("❌ No supported content encryption (A128GCM/A256GCM)")
        header = {"alg": "ECDH-ES", "enc": enc_alg, **({"kid": enc["kid"]} if "kid" in enc else {})}
        token = jwe.JWE(json.dumps(payload).encode(), protected=json.dumps(header))
        token.add_recipient(jwk.JWK(**{k: enc[k] for k in ("kty", "crv", "x", "y")}))
        form = {"response": token.serialize(compact=True)}
    else:
        form = {k: (json.dumps(v) if isinstance(v, dict) else v) for k, v in payload.items()}

    st, body, _ = http("POST", req["response_uri"], form=form)
    if st != 200:
        sys.exit(f"❌ Verifier answered HTTP {st}: {body[:300].decode(errors='replace')}")
    redirect = (json.loads(body) if body.strip().startswith(b"{") else {}).get("redirect_uri")
    print("✅ Presented" + (f" — continue at {redirect}" if redirect else ""))


def list_credentials():
    found = False
    for path, isd, mso in stored_credentials():
        found = True
        names = sorted(n for v in element_names(isd).values() for n in v)
        print(f"{os.path.basename(path)}\n   {mso['docType']}, {validity_label(mso)}"
              f"\n   issuer: {issuer_of(isd)}\n   {', '.join(names)}")
    if not found:
        print("No credentials stored.")


def main():
    global STORE
    ap = argparse.ArgumentParser(description="Minimal mdoc wallet (OID4VCI 1.0 pre-auth, OID4VP 1.0)")
    ap.add_argument("--store", default=STORE, help="storage folder (default: ./store)")
    ap.add_argument("--client-id", help="issue: identify to the token endpoint and put this in the "
                                        "proof's iss (for issuers that require it, e.g. --client-id my-wallet)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("issue").add_argument("link", nargs="?", help="offer link (prompted for if omitted)")
    p = sub.add_parser("present")
    p.add_argument("link", nargs="?", help="openid4vp link (prompted for if omitted)")
    p.add_argument("--yes", action="store_true", help="share without asking")
    sub.add_parser("list")
    a = ap.parse_args()
    STORE = os.path.abspath(a.store)
    if a.cmd in ("issue", "present") and not a.link:
        # Pasting at a prompt avoids shell quoting: an unquoted '&' in a link splits the command.
        try:
            a.link = input("Paste credential offer link: " if a.cmd == "issue" else "Paste openid4vp link: ").strip()
        except EOFError:
            a.link = ""
        if not a.link:
            sys.exit("❌ No link given")
    if a.cmd == "issue":
        issue(a.link, a.client_id)
    elif a.cmd == "present":
        present(a.link, a.yes)
    else:
        list_credentials()


if __name__ == "__main__":
    main()
