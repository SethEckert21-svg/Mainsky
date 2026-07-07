# Double Pivot Encryption

A prototype that encrypts both the **structure** and the **contents** of a
JSON-like Python dict using two key-derived "pivots" plus an authenticated
confidentiality layer.

> **Status: prototype.** The AES-GCM backend is suitable for real use with
> proper key management. The stdlib fallback is unreviewed and exists only so
> the module runs without third-party packages. Don't protect anything that
> actually matters with the fallback.

## Concept

| Stage | Name | What it does |
|-------|------|--------------|
| Pivot 1 | Structural Transform | Derive a deterministic permutation of the field names from `pivot1_key`, reorder the fields, wrap with restoration metadata, JSON-serialize, zlib-compress → a *structural blob*. |
| Pivot 2 | Interpretive Transform | Reverse the structural blob back into the original dict using the recorded permutation. |
| Confidentiality | AES-GCM / HMAC-CTR | Encrypt-and-authenticate the structural blob so it is neither readable nor tamperable without the master key. |

Three subkeys are derived from one master key via PBKDF2-HMAC-SHA256, each bound
to a distinct context so they are independent:

```
pivot1_key = KDF(master_key, "structural")      # drives the field permutation
pivot2_key = KDF(master_key, "interpretive")    # drives authentication
cipher_key = KDF(master_key, "confidentiality") # drives the cipher
```

## Install

```bash
pip install -r requirements.txt
```

`cryptography` is optional but **strongly recommended** — without it the module
silently falls back to the unreviewed stdlib construction.

## Usage

```python
from double_pivot_encryption import (
    double_pivot_encrypt, double_pivot_decrypt, active_backend,
)

print(active_backend())          # "AES-256-GCM" or "HMAC-SHA256-CTR (stdlib fallback)"

master_key = b"my-secret-master-key"
data = {"user_id": 123, "role": "admin"}

ciphertext = double_pivot_encrypt(data, master_key)   # -> bytes
restored   = double_pivot_decrypt(ciphertext, master_key)
assert restored == data
```

Run the built-in self-test / demo:

```bash
python3 double_pivot_encryption.py
```

With `cryptography` installed you should see `Confidentiality backend:
AES-256-GCM` and a ciphertext whose first byte is `01`. All five checks
(round-trip, confidentiality, nonce freshness, wrong-key rejection, tamper
rejection) should pass.

## Ciphertext layout

Every ciphertext begins with a one-byte **backend id** so decryption always
knows which construction to reverse.

```
AES-256-GCM   (id 0x01):  01 || nonce(12) || gcm_ciphertext_and_tag
stdlib HMAC-CTR (id 0x02):  02 || nonce(16) || hmac_tag(32) || ciphertext
```

- **AES-GCM** provides confidentiality + integrity in one primitive; the
  interpretive key is passed as associated data so it participates in
  authentication.
- **HMAC-CTR** is encrypt-then-MAC: a CTR keystream
  `HMAC-SHA256(cipher_key, nonce || counter)` XORed with the plaintext, then an
  `HMAC-SHA256(pivot2_key, nonce || ciphertext)` tag verified constant-time
  *before* decryption.

Both use a fresh random nonce per encryption, so encrypting identical input
twice yields different ciphertexts.

## Known limitations

- **Fallback is unreviewed.** Prefer AES-GCM (install `cryptography`).
- **Length leakage.** Pivot 1 compresses *before* the cipher runs, so
  ciphertext length correlates with plaintext compressibility (the CRIME/BREACH
  class of side channel). Fine for a prototype; know it before trusting it with
  adversarial data.
- **Key management is out of scope.** The master key is passed in directly;
  there is no key storage, rotation, or exchange.
- **Not a standard.** The wire format is ad hoc and versioned only by the
  `meta.version` field inside Pivot 1 and the backend id byte.
