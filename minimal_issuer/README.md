# Minimal OID4VCI Issuer

Single-file ISO mdoc issuer using OID4VCI 1.0 (pre-authorized code flow). The issuer-side
counterpart of `minimal_verifier/` and `minimal_wallet/`.

- **`minimal_issuer.py`** (~300 lines) — issues one mdoc credential type, default
  `org.iso.23220.photoid.1` with `age_over_18`

Deliberately left out: transaction codes, the authorization-code flow, credential response
encryption, status lists, batch issuance, DPoP, and multiple credential types.

## What It Does

1. Shows a QR code on a web page (a fresh, single-use offer per page load)
2. Wallet scans it and runs the pre-authorized code flow
3. Wallet sends a proof JWT for its device key; the issuer signs an mdoc bound to that key
4. Page updates to "Credential issued"

## Setup

### Prerequisites

```bash
pip install flask pyjwt cryptography cbor2 qrcode[pil]
```

### Signing keys

On first run the issuer generates its own **IACA** (root, CA) and **DSC** (document signer,
EKU `1.0.18013.5.1.2`) into `keys/`. A wallet or verifier only trusts the credentials if it
trusts `keys/iaca.crt` — give that file (never the `.key` files) to whoever must accept them.

To sign with an existing DSC instead (for example one whose IACA your verifiers already
trust), point the config at it:

```json
"dsc_key": "/path/to/dsc.key",
"dsc_cert": "/path/to/dsc.crt"
```

### SSL (Required for phone wallets)

The app runs plain HTTP. Put a reverse proxy in front for HTTPS — Caddy renews Let's Encrypt
certificates automatically:

```
# Caddyfile
issuer.example.com {
    reverse_proxy localhost:8090
}
```

### Configuration

Edit `minimal_issuer_config.json`:

```json
{
  "base_url": "https://issuer.example.com",
  "port": 8090,
  "issuer_name": "Minimal Issuer",
  "country": "NZ",
  "credential_configuration_id": "photoid",
  "doctype": "org.iso.23220.photoid.1",
  "namespace": "org.iso.23220.1",
  "validity_days": 365,
  "claims": {
    "family_name": "Citizen",
    "birth_date": {"full-date": "1990-01-01"},
    "age_over_18": true,
    "portrait": {"file": "portrait.jpg"}
  }
}
```

`base_url` must be the public HTTPS URL the wallet reaches. Claim values are plain JSON, plus
two special forms: `{"full-date": "YYYY-MM-DD"}` becomes a CBOR full-date (tag 1004) and
`{"file": "path"}` becomes a byte string (e.g. a JPEG portrait). Booleans stay booleans.

For an mDL instead, set `doctype` to `org.iso.18013.5.1.mDL` and `namespace` to
`org.iso.18013.5.1`.

## Run

```bash
python minimal_issuer.py
```

Open `base_url` in a browser and scan the QR with a wallet. For a CLI wallet such as
`minimal_wallet`, get a fresh offer link from `GET /new-offer`:

```bash
curl -s http://localhost:8090/new-offer
python ../minimal_wallet/minimal_wallet.py issue      # paste the credential_offer link
```

## Files

| File | Purpose |
|------|---------|
| `minimal_issuer.py` | The issuer |
| `minimal_issuer_config.json` | URL, port, doctype, claims, key paths |
| `portrait.jpg` | Placeholder portrait (96×120 black JPEG, 819 bytes), issued as the `portrait` claim |
| `keys/iaca.crt`, `keys/iaca.key` | Generated IACA root — share the `.crt` only |
| `keys/dsc.crt`, `keys/dsc.key` | Generated document signer, signed by the IACA |

## Protocol Flow

```
Browser          Issuer                         Wallet
   |  GET /          |                             |
   |<-- QR page -----|                             |
   |                 |  scan QR (offer by reference)
   |                 |<-- GET /offer/{id} ---------|
   |                 |<-- GET /.well-known/openid-credential-issuer
   |                 |<-- GET /.well-known/oauth-authorization-server
   |                 |<-- POST /token (pre-authorized_code, single use)
   |                 |<-- POST /nonce -------------|
   |                 |<-- POST /credential (Bearer + proof JWT with nonce)
   |                 |--- {"credentials":[{"credential": base64url IssuerSigned}]} -->
   |  poll /status   |                             |
   |<-- issued ------|                             |
```

## Security notes

- Pre-authorized codes, access tokens and nonces are random, single-use and held in memory
  (lost on restart). Tokens and nonces expire after 5 minutes.
- The proof JWT must be `typ: openid4vci-proof+jwt`, ES256, carry a public `jwk`, have
  `aud` = `base_url`, a fresh `iat`, and an unused nonce from this issuer.
- The token response also carries `c_nonce` (pre-1.0 behaviour) so wallets that never call
  `/nonce` still work. OID4VCI 1.0 final wallets use `/nonce` and ignore it.
- Anyone who can load the QR page gets a credential: there is no user authentication. This is
  a test issuer.
