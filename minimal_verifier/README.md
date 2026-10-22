# Minimal OID4VP Verifier

Single-file age-verification verifiers for ISO 18013-5 / 23220 mdoc credentials. The verifier
counterpart of `minimal_issuer/` and `minimal_wallet/`. Two versions, same checks, different
protocol:

- **`minimal_verifier_1_0.py`** (~450 lines) — **OpenID for Verifiable Presentations 1.0
  (Final)**, mdoc profile (Appendix B.2). Use this with wallets that support OID4VP 1.0.
- **`minimal_verifier_18013_7.py`** (~485 lines) — the pre-1.0 OpenID4VP profile of
  **ISO/IEC 18013-7 (2024) Annex B**, which many production mdoc wallets still implement.
  See [ISO 18013-7 version](#iso-18013-7-version).

Everything below describes `minimal_verifier_1_0.py` unless stated otherwise.

## What It Does

1. Shows a QR code (and an "Open in Wallet" link) for a fresh, signed presentation request
2. The wallet fetches the request, asks the user, and posts an encrypted response
3. The verifier checks the credential fully and the page shows the result

Every presentation is checked for:

| Check | Meaning |
|---|---|
| `signature` | issuerAuth COSE signature verifies with the document signer certificate (DSC) |
| `issuer_trusted` | the DSC is signed by an IACA in `trusted_iacas/`, and the IACA and DSC are in date |
| `not_expired` | now is inside the MSO's `validFrom`–`validUntil` window |
| `digests_valid` | every disclosed element hashes to its MSO `valueDigests` entry |
| `doctype_ok` | document docType = MSO docType = the docType requested |
| `device_auth` | the device signature verifies over the OID4VP 1.0 SessionTranscript (holder binding, bound to this request's nonce and this verifier's key) |

It also reports over-disclosure (elements returned that were not requested) and rejects a second
response for a session that has already answered. The result is `verified` only when every check
passes and `age_over_18` is `true`.

## Protocol

**Request** (signed JWT, `typ: oauth-authz-req+jwt`, `x5c` header, served at `request_uri`):

| Parameter | Value |
|---|---|
| `client_id` | `x509_san_dns:<your DNS name>` (Client Identifier Prefix included) |
| `response_mode` | `direct_post.jwt` |
| `dcql_query` | from the config (default: `org.iso.23220.photoid.1` / `age_over_18`) |
| `client_metadata` | `jwks` (ECDH-ES P-256 key with `alg` and `kid`), `encrypted_response_enc_values_supported: ["A256GCM"]`, `vp_formats_supported.mso_mdoc` with COSE algorithm ids |

Wallet link: `openid4vp://?client_id=...&request_uri=...`

**Response**: a JWE (ECDH-ES, A256GCM) posted as `response=` to `response_uri`, containing
`{"vp_token": {"<DCQL query id>": ["<base64url DeviceResponse>"]}, "state": "..."}`.

**Device signature transcript** (OID4VP 1.0 B.2.6.1):

```
SessionTranscript = [null, null, ["OpenID4VPHandover",
                     SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]]
```

`jwkThumbprint` is the RFC 7638 SHA-256 thumbprint (bytes) of the verifier's encryption key.

## ISO 18013-7 version

`minimal_verifier_18013_7.py` has the same checks, pages and endpoints, plus
`GET /.well-known/oauth-client` (some wallets fetch it). Only the protocol differs:

| | `minimal_verifier_1_0.py` | `minimal_verifier_18013_7.py` |
|---|---|---|
| Wallet link | `openid4vp://` | `mdoc-openid4vp://` |
| `client_id` | `x509_san_dns:<dns>` (prefix in the value) | `<dns>`, plus a separate `client_id_scheme=x509_san_dns` |
| Query | `dcql_query` | `presentation_definition` |
| Client metadata | `vp_formats_supported`, `encrypted_response_enc_values_supported` | `vp_formats`, `authorization_encrypted_response_alg/enc` |
| `vp_token` | object keyed by DCQL query id | base64url DeviceResponse string, with `presentation_submission` |
| Wallet nonce | none | `mdoc_generated_nonce`, sent base64url in the JWE `apu` header |

Its device signature is verified against the ISO 18013-7 OpenID4VP handover:

```
SessionTranscript = [null, null, [SHA-256(cbor([client_id, mdoc_nonce])),
                                  SHA-256(cbor([response_uri, mdoc_nonce])),
                                  nonce]]
```

`client_id` is the bare DNS name (no prefix), `mdoc_nonce` comes from the JWE `apu` header, and
`nonce` is the request's nonce. It reads `presentation_definition` from the config (default:
`org.iso.23220.photoid.1` / `age_over_18`); everything else in the configuration is shared.

If a wallet fails with the 1.0 version but supports remote presentation, try this one.

## Setup

### Prerequisites

```bash
pip install flask pyjwt cryptography jwcrypto cbor2 qrcode[pil]
```

### Request signing certificate

An EC P-256 key and certificate with:
- a `dNSName` Subject Alternative Name equal to your `client_id` DNS name
- Extended Key Usage `1.0.18013.5.1.6` (mdoc reader authentication)
- signed by a CA the target wallets trust

Wallets check the request signature against this certificate and the `client_id` against its
SAN. Wallets that do not trust its CA usually still require the `response_uri` host to equal
the `client_id` DNS name.

### Trusted issuers

Put the IACA certificate (PEM or DER) of every credential issuer you accept in `trusted_iacas/`
(or the folder named by `vical_dir`). With an empty folder every presentation fails
`issuer_trusted`.

### HTTPS

The app serves plain HTTP. Put a reverse proxy in front for HTTPS, for example Caddy, which
obtains and renews certificates automatically:

```
verifier.example.com {
    reverse_proxy localhost:8080
}
```

### Configuration

Copy `verifier_config_1_0.example.json` to `verifier_config.json` and edit it:

| Key | Purpose |
|---|---|
| `client_id` | your DNS name, without prefix (the `x509_san_dns:` prefix is added) |
| `base_url` | public HTTPS URL; `response_uri` and `request_uri` are built from it |
| `port` | local port |
| `signing_key`, `signing_cert` | request signing key and certificate (PEM) |
| `encryption_key` | response encryption JWK; generated on first run if missing |
| `vical_dir` | folder of trusted IACA certificates (default `trusted_iacas`) |
| `dcql_query` | what to request (`minimal_verifier_1_0.py`) |
| `presentation_definition` | what to request (`minimal_verifier_18013_7.py`) |

Optional: `client_id_prefix` (1.0 only, default `x509_san_dns`), `wallet_scheme` (default
`openid4vp://` for 1.0, `mdoc-openid4vp://` for 18013-7).
Relative paths are resolved against the config file's folder.

## Run

```bash
python minimal_verifier_1_0.py                       # uses ./verifier_config.json
python minimal_verifier_1_0.py --config other.json
python minimal_verifier_18013_7.py                   # same config, ISO 18013-7 protocol
```

Open `base_url` in a browser and scan the QR, or use "Open in Wallet". Each page load creates a
new session; the page polls `/status/<session>` and shows the result for that session.
`/last` shows the newest result received, with every check, regardless of session.

## Files

| File | Purpose |
|------|---------|
| `minimal_verifier_1_0.py` | The verifier (OID4VP 1.0) |
| `minimal_verifier_18013_7.py` | The verifier (ISO 18013-7, pre-1.0 OID4VP) |
| `verifier_config_1_0.example.json` | Example configuration |
| `signing.key`, `signing.cert` | Request signing key and certificate (you provide; keep the key private) |
| `enc_jwk.json` | Response encryption key (generated; private) |
| `trusted_iacas/` | Trusted issuer IACA certificates |

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | QR page for a new session |
| `GET /v2/presentations/sessions/{sid}/requests/{nonce}` | Signed request object |
| `POST /v2/presentations/sessions/response` | Encrypted response from the wallet |
| `GET /.well-known/oauth-client` | Client metadata (`minimal_verifier_18013_7.py` only) |
| `GET /status/{sid}` | Result for one session (polled by the page) |
| `GET /last` | Newest result received |

## Notes

- Sessions are held in memory; a restart forgets them.
- The encryption key is static across sessions. Anyone holding `enc_jwk.json` can decrypt past
  responses; rotate it, or generate a key per session, for anything beyond testing.
- This is a test verifier: there is no rate limiting or session expiry.
