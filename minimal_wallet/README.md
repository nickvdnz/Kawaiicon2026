# Minimal Wallet

Single-file ISO mdoc wallet: the holder-side counterpart of `minimal_issuer/` and
`minimal_verifier/minimal_verifier_1_0.py`.

- **`minimal_wallet.py`** (~430 lines)

| Command | Protocol |
|---|---|
| `issue <offer link>` | OID4VCI 1.0, pre-authorized code flow |
| `present <openid4vp link>` | OID4VP 1.0, DCQL, `mso_mdoc`, signed request, `direct_post.jwt` or `direct_post` |
| `list` | Stored credentials |

Deliberately left out: draft protocol versions, the authorization-code flow, transaction codes,
DPoP, batch and deferred issuance, encrypted credential responses, SD-JWT, unsigned requests,
proximity (BLE/NFC) presentation, and multiple DCQL credential queries.

## Setup

```bash
pip install cryptography cbor2 pyjwt jwcrypto
```

## Use

```bash
# 1. Get a credential (e.g. from minimal_issuer: open its page, or GET /new-offer)
python minimal_wallet.py issue
Paste credential offer link: openid-credential-offer://?credential_offer_uri=...

# 2. See what's stored
python minimal_wallet.py list

# 3. Present to a verifier (e.g. the minimal_verifier_1_0 page's "Open in Wallet" link)
python minimal_wallet.py present
Paste openid4vp link: openid4vp://?client_id=...&request_uri=...
```

Leave the link off the command line and the wallet prompts for it. Pasting at the prompt needs
no quoting. The link can also be given as an argument, but then it **must be in single quotes**:
links contain `&`, and an unquoted `&` makes the shell run the first half in the background and
drop the rest, so the wallet only sees the `client_id` part:

```bash
python minimal_wallet.py present 'openid4vp://?client_id=...&request_uri=...'
```

`present` shows who is asking, for which elements, which credential and issuer, and where the
response goes, then asks `Share? [y/N]`. Add `--yes` to skip the prompts. `--store DIR` uses
another storage folder.

`list` shows credentials newest first (by the MSO signing time), each with its docType, validity
(`valid`, `EXPIRED` or `NOT YET VALID`), issuer (the document signer certificate subject) and
elements.

### Issuers that require `iss` in the proof

By default issuance is anonymous pre-auth: no `client_id` at the token endpoint and no `iss` in
the proof JWT, as OID4VCI 1.0 Appendix F.1 requires ("MUST be omitted" for anonymous access).
Some issuers nevertheless reject a proof without `iss` (typically `invalid_proof`). Pass
`--client-id` to identify the wallet: it is sent to the token endpoint and used as the proof's
`iss`, which is then spec-correct because the access is no longer anonymous.

```bash
python minimal_wallet.py --client-id my-wallet issue
```

If an issuer offers no nonce endpoint and returns no `c_nonce`, the proof is sent without a
nonce.

### Choosing between credentials

A credential matches when its docType equals the request's `doctype_value` and it holds every
requested element. One match is used directly. With several, the wallet lists them newest first
with issuer and validity, and you pick a number (Enter = the newest):

```
🗂  3 credentials match:
   [1] org.iso.23220.photoid.1-20261013-143610.cbor
       issuer: CN=Minimal Issuer DSC,C=NZ
       valid, until 2027-10-13
   [2] org.iso.23220.photoid.1-20260721-094500.cbor
       issuer: CN=Example Issuer DSC,O=Example Org,C=NZ
       valid, until 2026-10-19
   [3] org.iso.23220.photoid.1-20260602-114246.cbor
       issuer: CN=Other Issuer Document Signer,C=NZ
       EXPIRED, until 2026-09-02
   Choose 1-3 (Enter = 1, newest): 
```

Expired and not-yet-valid credentials are offered too, labelled, so they can be presented on
purpose (for example to test a verifier's expiry check). `--yes` takes the newest without asking.

## What it checks and does

**Issue**
- Fetches the offer (by reference or by value), issuer metadata and authorization server metadata
- Swaps the pre-authorized code for an access token, gets a fresh `c_nonce` from the nonce endpoint
- Sends a proof JWT (`openid4vci-proof+jwt`, ES256, `jwk` header, `aud` = issuer, `iat`, `nonce`)
- Refuses a credential that is not bound to its own device key

**Present**
- Request object must be signed (`typ: oauth-authz-req+jwt`, `x5c`), and the signature must verify
  with the `x5c` leaf certificate
- `client_id` must use `x509_san_dns:` (name must be a dNSName SAN of the leaf) or `x509_hash:`
  (hash of the leaf), and match the `client_id` in the link
- If the `x5c` chain ends at a root in `store/trusted_verifiers/`, the verifier is trusted.
  If not, the wallet only continues when the `response_uri` host equals the `x509_san_dns` name,
  so a validly signed request cannot send the credential to a different host
- Matches the first DCQL credential query by docType and requested elements, and discloses only
  those elements
- Signs DeviceAuthentication over the OID4VP 1.0 SessionTranscript
  `[null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]]`
  (detached COSE_Sign1, ES256)
- Encrypts the response (ECDH-ES, A128GCM or A256GCM per `encrypted_response_enc_values_supported`)
  to the verifier's key, with `kid`, and POSTs `response=<JWE>` to `response_uri`

All HTTPS connections verify certificates.

## Storage

| Path | Purpose |
|------|---------|
| `store/device_key.pem` | P-256 device key, generated on first use (unencrypted, demo only) |
| `store/creds/*.cbor` | Credentials (`IssuerSigned`), named by docType and issue time (`-2`, `-3`… if two land in the same second; never overwritten) |
| `store/trusted_verifiers/` | Root certificates trusted to sign verifier requests (PEM or DER) |

One device key is shared by every credential, so a verifier could link presentations of
different credentials. Real wallets use a key per credential.

## Tested (2026-10-13)

- Full loop locally: `minimal_issuer` → `issue` → `present` → `minimal_verifier_1_0.py`, every
  verifier check passing (signature, issuer trust, validity, digests, docType, device signature)
- Over the internet: presented to a deployed `minimal_verifier_1_0.py` behind HTTPS, all checks pass
- Refused as expected: tampered request payload, request signed by a key not in `x5c`,
  `client_id` not in the certificate SAN, link `client_id` differing from the signed request,
  and (with no trusted root) a `response_uri` on another host
