"""
Double Pivot Encryption (prototype)
===================================

Double Pivot Encryption encrypts both the **structure** and the **contents**
of a JSON-like object using key-derived pivots plus a confidentiality layer.

    Pivot 1 -- Structural Transform
        Scramble the *structure*: derive a deterministic permutation of the
        object's field names from ``pivot1_key``, reorder the fields, wrap the
        result with restoration metadata, serialize, and compress. This yields
        an intermediate structural blob.

    Pivot 2 -- Interpretive Transform
        Restore *meaning*: reverse the structural blob back into the original
        object using the recorded permutation.

    Confidentiality layer (encrypt-then-MAC)
        The structural blob is enciphered with a keystream cipher and
        authenticated with an HMAC tag, so the ciphertext is neither readable
        nor tamperable without the master key.

Three keys are derived from a single master key so each concern has its own
independent secret:

    pivot1_key = KDF(master_key, context="structural")     # drives the scramble
    pivot2_key = KDF(master_key, context="interpretive")   # drives the auth tag
    cipher_key = KDF(master_key, context="confidentiality")# drives the keystream

CONFIDENTIALITY CONSTRUCTION (pluggable backend)
------------------------------------------------
The confidentiality layer prefers a **vetted AEAD** and falls back to a
stdlib-only construction only when the library is unavailable:

  * Backend 0x01 -- AES-256-GCM via the ``cryptography`` package (preferred).
    This is real, reviewed authenticated encryption. Used automatically when
    ``cryptography`` imports successfully.

  * Backend 0x02 -- stdlib fallback: a hand-rolled HMAC-SHA256 counter-mode
    (CTR) keystream cipher with **encrypt-then-MAC**::

        keystream_block(i) = HMAC-SHA256(cipher_key, nonce || counter_i)
        ciphertext         = plaintext XOR keystream
        tag                = HMAC-SHA256(pivot2_key, nonce || ciphertext)

Every ciphertext begins with a one-byte backend id so decryption always knows
which construction to reverse; decrypting with the wrong backend/key/data is
rejected by the authentication check.

Both backends use a fresh random nonce per encryption and verify authenticity
(constant-time) *before* decrypting, then reverse the pivots.

The AES-GCM backend is suitable for real use with proper key management. The
stdlib fallback has the correct *shape* of an AEAD (unique nonce, CTR
keystream, encrypt-then-MAC, constant-time check) but is unreviewed and slow;
it exists only so the module still functions without third-party packages.
Prefer running with ``cryptography`` installed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import zlib

def _try_import_aesgcm():
    """Import AES-GCM, silencing native-backend noise on failure.

    A broken native backend can print a Rust panic backtrace straight to the
    real stderr file descriptor and raise a non-``Exception`` (e.g. a
    ``PanicException``). We temporarily redirect fd 2 to /dev/null and catch
    ``BaseException`` so a broken install degrades quietly to the fallback.
    """
    import os as _os
    import sys

    sys.stderr.flush()
    saved_fd = _os.dup(2)
    devnull = _os.open(_os.devnull, _os.O_WRONLY)
    try:
        _os.dup2(devnull, 2)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except BaseException:  # noqa: BLE001 - intentionally broad; see docstring
        return None
    finally:
        _os.dup2(saved_fd, 2)
        _os.close(saved_fd)
        _os.close(devnull)


AESGCM = _try_import_aesgcm()
_HAVE_AESGCM = AESGCM is not None

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

_KDF_ITERATIONS = 100_000
_KDF_SALT = b"double-pivot-encryption/v1"

# Backend identifiers (first byte of every ciphertext).
_BACKEND_AESGCM = 0x01
_BACKEND_HMAC_CTR = 0x02

# AES-GCM parameters.
_GCM_NONCE_LEN = 12

# stdlib HMAC-CTR fallback parameters.
_NONCE_LEN = 16
_TAG_LEN = 32  # HMAC-SHA256 digest size


def kdf(master_key: bytes, context: str, length: int = 32) -> bytes:
    """Derive a context-bound subkey from ``master_key``.

    Uses PBKDF2-HMAC-SHA256 from the standard library. The ``context`` string
    is folded into the salt so that different contexts (e.g. "structural",
    "interpretive", "confidentiality") yield independent, unrelated keys from
    the same master key.

    This is intentionally simple, not production-tuned.
    """
    if isinstance(master_key, str):
        master_key = master_key.encode("utf-8")
    salt = _KDF_SALT + b"|" + context.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", master_key, salt, _KDF_ITERATIONS, dklen=length)


# ---------------------------------------------------------------------------
# Confidentiality layer: AES-256-GCM (preferred) or stdlib HMAC-CTR fallback
# ---------------------------------------------------------------------------


def active_backend() -> str:
    """Return the name of the confidentiality backend that will be used."""
    return "AES-256-GCM" if _HAVE_AESGCM else "HMAC-SHA256-CTR (stdlib fallback)"


def _keystream(cipher_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate ``length`` keystream bytes via HMAC-SHA256 in counter mode.

    Block ``i`` is ``HMAC-SHA256(cipher_key, nonce || uint64_be(i))``. Blocks
    are concatenated and truncated to ``length``.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(cipher_key, nonce + struct.pack(">Q", counter),
                         hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, keystream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream))


def _seal(plaintext: bytes, cipher_key: bytes, mac_key: bytes) -> bytes:
    """Encrypt + authenticate ``plaintext``.

    Uses AES-256-GCM when available, otherwise the stdlib HMAC-CTR fallback.
    The returned blob is ``backend_id(1) || backend-specific bytes``.
    """
    if _HAVE_AESGCM:
        nonce = os.urandom(_GCM_NONCE_LEN)
        # AES-GCM authenticates internally; bind mac_key in as associated data
        # so the "interpretive" key still participates in authentication.
        ciphertext = AESGCM(cipher_key).encrypt(nonce, plaintext, mac_key)
        return bytes([_BACKEND_AESGCM]) + nonce + ciphertext

    nonce = os.urandom(_NONCE_LEN)
    ciphertext = _xor(plaintext, _keystream(cipher_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return bytes([_BACKEND_HMAC_CTR]) + nonce + tag + ciphertext


def _open(blob: bytes, cipher_key: bytes, mac_key: bytes) -> bytes:
    """Verify + decrypt a blob produced by :func:`_seal`.

    Dispatches on the leading backend id. Raises ``ValueError`` on wrong key,
    tampering, an unknown backend, or truncated input.
    """
    if not blob:
        raise ValueError("Empty ciphertext")
    backend, body = blob[0], blob[1:]

    if backend == _BACKEND_AESGCM:
        if not _HAVE_AESGCM:
            raise ValueError("Ciphertext requires AES-GCM but 'cryptography' "
                             "is unavailable in this environment")
        if len(body) < _GCM_NONCE_LEN:
            raise ValueError("Ciphertext too short to contain a nonce")
        nonce, ciphertext = body[:_GCM_NONCE_LEN], body[_GCM_NONCE_LEN:]
        try:
            return AESGCM(cipher_key).decrypt(nonce, ciphertext, mac_key)
        except Exception as exc:  # InvalidTag and friends
            raise ValueError("Authentication failed: wrong key or tampered "
                             "ciphertext") from exc

    if backend == _BACKEND_HMAC_CTR:
        if len(body) < _NONCE_LEN + _TAG_LEN:
            raise ValueError("Ciphertext too short to contain nonce and tag")
        nonce = body[:_NONCE_LEN]
        tag = body[_NONCE_LEN:_NONCE_LEN + _TAG_LEN]
        ciphertext = body[_NONCE_LEN + _TAG_LEN:]
        expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed: wrong key or tampered ciphertext")
        return _xor(ciphertext, _keystream(cipher_key, nonce, len(ciphertext)))

    raise ValueError(f"Unknown confidentiality backend id: {backend}")


# ---------------------------------------------------------------------------
# Permutation helpers
# ---------------------------------------------------------------------------


def _derive_permutation(keys: list[str], pivot1_key: bytes) -> list[int]:
    """Derive a deterministic permutation of ``keys`` from ``pivot1_key``.

    Each field name is assigned a sort rank equal to an HMAC of the name under
    ``pivot1_key``. Sorting by that rank produces a key-dependent, deterministic
    ordering. Returns the permutation as the list of *original* indices in their
    new order (i.e. ``new_order[i]`` is the original index placed at slot ``i``).
    """
    ranked = []
    for original_index, name in enumerate(keys):
        rank = hmac.new(pivot1_key, name.encode("utf-8"), hashlib.sha256).digest()
        ranked.append((rank, original_index))
    ranked.sort(key=lambda pair: pair[0])
    return [original_index for _rank, original_index in ranked]


# ---------------------------------------------------------------------------
# Pivot 1: Structural Transform
# ---------------------------------------------------------------------------


def pivot1_structural_transform(plaintext_obj: dict, pivot1_key: bytes) -> bytes:
    """Pivot 1 -- scramble the structure into a compressed structural blob.

    Steps:
      1. Derive a deterministic permutation of the field names from ``pivot1_key``.
      2. Reorder the fields according to that permutation.
      3. Build ``meta`` recording how to undo the transform (permutation +
         original key order).
      4. Wrap ``{"meta": ..., "payload": <reordered dict>}``.
      5. JSON-serialize and zlib-compress.

    Returns the compressed structural blob. Confidentiality/authenticity are
    applied on top of this by the high-level ``double_pivot_encrypt``.
    """
    original_keys = list(plaintext_obj.keys())
    permutation = _derive_permutation(original_keys, pivot1_key)

    # Reorder the fields. json objects preserve insertion order in Python.
    reordered = {original_keys[i]: plaintext_obj[original_keys[i]] for i in permutation}

    meta = {
        "version": 2,
        "field_count": len(original_keys),
        "permutation": permutation,
        "original_keys": original_keys,
    }

    container = {"meta": meta, "payload": reordered}
    serialized = json.dumps(container, separators=(",", ":")).encode("utf-8")
    return zlib.compress(serialized, level=9)


# ---------------------------------------------------------------------------
# Pivot 2: Interpretive Transform
# ---------------------------------------------------------------------------


def pivot2_interpretive_transform(structural_blob: bytes) -> dict:
    """Pivot 2 -- reverse the structural blob back into the original dict.

    Steps:
      1. Decompress and deserialize the structural blob.
      2. Use the stored permutation / original key order to restore the
         original field ordering.
      3. Return the reconstructed original dict.

    Authenticity is verified by the confidentiality layer *before* this runs, so
    by the time Pivot 2 sees the blob it is already trusted.
    """
    try:
        serialized = zlib.decompress(structural_blob)
        container = json.loads(serialized.decode("utf-8"))
    except (zlib.error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Structural blob is corrupt or malformed") from exc

    meta = container["meta"]
    payload = container["payload"]
    original_keys = meta["original_keys"]

    # Rebuild in original field order. payload is keyed by field name, so we
    # simply re-emit the keys in their original sequence.
    restored = {}
    for original_index in range(meta["field_count"]):
        name = original_keys[original_index]
        restored[name] = payload[name]
    return restored


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


def double_pivot_encrypt(plaintext_obj: dict, master_key: bytes) -> bytes:
    """Encrypt a dict: structural scramble (Pivot 1) + confidentiality layer.

    Derives all three subkeys from ``master_key``, applies Pivot 1 to produce a
    structural blob, then enciphers and authenticates it (encrypt-then-MAC).
    Returns ``nonce || tag || ciphertext``.
    """
    pivot1_key = kdf(master_key, context="structural")
    pivot2_key = kdf(master_key, context="interpretive")
    cipher_key = kdf(master_key, context="confidentiality")

    structural_blob = pivot1_structural_transform(plaintext_obj, pivot1_key)
    return _seal(structural_blob, cipher_key, pivot2_key)


def double_pivot_decrypt(ciphertext: bytes, master_key: bytes) -> dict:
    """Decrypt: verify + decipher the confidentiality layer, then Pivot 2.

    Derives the subkeys from ``master_key``, verifies the auth tag and decrypts
    to recover the structural blob (raising ``ValueError`` on wrong key or
    tampering), then applies Pivot 2 to restore the original dict.
    """
    pivot2_key = kdf(master_key, context="interpretive")
    cipher_key = kdf(master_key, context="confidentiality")

    structural_blob = _open(ciphertext, cipher_key, pivot2_key)
    return pivot2_interpretive_transform(structural_blob)


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    plaintext = {
        "user_id": 123,
        "role": "admin",
        "permissions": ["read", "write", "delete"],
        "timestamp": "2026-07-07T07:30:00",
    }
    master_key = b"my-secret-master-key"

    print(f"Confidentiality backend: {active_backend()}")
    print()

    ciphertext = double_pivot_encrypt(plaintext, master_key)
    decrypted = double_pivot_decrypt(ciphertext, master_key)

    hex_preview = ciphertext[:32].hex()
    print("Original plaintext:")
    print(f"  {plaintext}")
    print()
    print("Ciphertext:")
    print(f"  length     : {len(ciphertext)} bytes")
    print(f"  hex preview: {hex_preview}{'...' if len(ciphertext) > 32 else ''}")
    print()
    print("Decrypted plaintext:")
    print(f"  {decrypted}")
    print()

    assert decrypted == plaintext, "Round-trip failed: decrypted != original"
    print("OK: decrypted == original")

    # Confidentiality: the compressed structural blob must NOT appear in the
    # clear inside the ciphertext.
    assert plaintext["role"].encode() not in ciphertext, "Plaintext leaked in ciphertext"
    print("OK: plaintext values not visible in ciphertext")

    # Nonce freshness: encrypting the same input twice yields different output.
    ciphertext2 = double_pivot_encrypt(plaintext, master_key)
    assert ciphertext != ciphertext2, "Ciphertext should differ across encryptions"
    print("OK: fresh nonce produces distinct ciphertexts")

    # Wrong key must fail authentication.
    try:
        double_pivot_decrypt(ciphertext, b"wrong-master-key")
    except ValueError as exc:
        print(f"OK: authentication correctly rejected wrong key ({exc})")
    else:
        raise AssertionError("Expected authentication failure with wrong key")

    # Tampering must fail authentication.
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01
    try:
        double_pivot_decrypt(bytes(tampered), master_key)
    except ValueError as exc:
        print(f"OK: authentication correctly rejected tampering ({exc})")
    else:
        raise AssertionError("Expected authentication failure on tampered ciphertext")
