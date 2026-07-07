"""
Double Pivot Encryption (prototype)
===================================

Double Pivot Encryption is a *structural* obfuscation scheme. Instead of only
encrypting raw bytes, it encrypts the **shape and interpretation** of a
JSON-like object using two independent, key-derived pivots.

    Pivot 1 -- Structural Transform
        Scramble the *structure*: derive a deterministic permutation of the
        object's field names, reorder the fields, wrap the result together with
        authenticated metadata, serialize, and compress. The output is the
        intermediate ciphertext.

    Pivot 2 -- Interpretive Transform
        Restore *meaning*: decompress and deserialize, validate the metadata
        (integrity/authenticity check), then use the recorded permutation to
        reverse Pivot 1 and reconstruct the original object.

Two keys are derived from a single master key so that each pivot has its own,
independent secret:

    pivot1_key = KDF(master_key, context="structural")   # drives the scramble
    pivot2_key = KDF(master_key, context="interpretive")  # drives the auth tag

NOTE ON DESIGN
--------------
The permutation is *stored* in ``meta`` (not re-derived on the decrypt side)
and is authenticated with an HMAC keyed by ``pivot2_key``. This is a deliberate
reconciliation: Pivot 1 owns "scramble + wrap + authenticate" while Pivot 2 owns
"validate + reverse + restore", and the two pivots use genuinely independent
keys while still round-tripping correctly.

This is a PROTOTYPE. It demonstrates the structure of the idea. It does **not**
provide confidentiality: the payload is only reordered and compressed, never
enciphered, so anyone can read it. Treat this as a structural/authenticity
experiment, not as encryption in the cryptographic sense.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import zlib

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

_KDF_ITERATIONS = 100_000
_KDF_SALT = b"double-pivot-encryption/v1"


def kdf(master_key: bytes, context: str, length: int = 32) -> bytes:
    """Derive a context-bound subkey from ``master_key``.

    Uses PBKDF2-HMAC-SHA256 from the standard library. The ``context`` string
    is folded into the salt so that different contexts (e.g. "structural" vs
    "interpretive") yield independent, unrelated keys from the same master key.

    This is intentionally simple, not production-tuned.
    """
    if isinstance(master_key, str):
        master_key = master_key.encode("utf-8")
    salt = _KDF_SALT + b"|" + context.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", master_key, salt, _KDF_ITERATIONS, dklen=length)


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


def pivot1_structural_transform(plaintext_obj: dict, pivot1_key: bytes,
                                pivot2_key: bytes) -> bytes:
    """Pivot 1 -- scramble the structure and produce intermediate ciphertext.

    Steps:
      1. Derive a deterministic permutation of the field names from ``pivot1_key``.
      2. Reorder the fields according to that permutation.
      3. Build ``meta`` describing how to undo the transform, including the
         permutation and an HMAC authentication tag keyed by ``pivot2_key``.
      4. Wrap ``{"meta": ..., "payload": <reordered dict>}``.
      5. JSON-serialize and zlib-compress.

    Returns the compressed bytes (the intermediate ciphertext).

    ``pivot2_key`` is used only to compute the authentication tag, so that the
    tag can be validated by Pivot 2 under its own independent key.
    """
    original_keys = list(plaintext_obj.keys())
    permutation = _derive_permutation(original_keys, pivot1_key)

    # Reorder the fields. json objects preserve insertion order in Python.
    reordered = {original_keys[i]: plaintext_obj[original_keys[i]] for i in permutation}

    meta = {
        "version": 1,
        "field_count": len(original_keys),
        # The permutation lets Pivot 2 restore the original order without having
        # to re-derive it (and thus without needing pivot1_key).
        "permutation": permutation,
        "original_keys": original_keys,
    }

    # Authenticate the meta + payload together under pivot2_key. We compute the
    # tag over a canonical serialization so both sides agree byte-for-byte.
    meta_no_tag = dict(meta)
    auth_input = _canonical_bytes({"meta": meta_no_tag, "payload": reordered})
    meta["auth_tag"] = hmac.new(pivot2_key, auth_input, hashlib.sha256).hexdigest()

    container = {"meta": meta, "payload": reordered}
    serialized = json.dumps(container, separators=(",", ":")).encode("utf-8")
    return zlib.compress(serialized, level=9)


# ---------------------------------------------------------------------------
# Pivot 2: Interpretive Transform
# ---------------------------------------------------------------------------


def pivot2_interpretive_transform(intermediate_ciphertext: bytes,
                                  pivot2_key: bytes) -> dict:
    """Pivot 2 -- validate, reverse the structure, and restore meaning.

    Steps:
      1. Decompress and deserialize the intermediate ciphertext.
      2. Recompute the authentication tag over ``meta`` + ``payload`` under
         ``pivot2_key`` and compare it (constant-time) with the stored tag.
         Raise ``ValueError`` on mismatch or tampering.
      3. Use the stored permutation to reverse Pivot 1's reordering.
      4. Return the reconstructed original dict.
    """
    try:
        serialized = zlib.decompress(intermediate_ciphertext)
        container = json.loads(serialized.decode("utf-8"))
    except (zlib.error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Ciphertext is corrupt or malformed") from exc

    meta = container["meta"]
    payload = container["payload"]

    # --- Validation: recompute the auth tag under pivot2_key --------------
    stored_tag = meta.get("auth_tag")
    if stored_tag is None:
        raise ValueError("Missing authentication tag")

    meta_no_tag = {k: v for k, v in meta.items() if k != "auth_tag"}
    auth_input = _canonical_bytes({"meta": meta_no_tag, "payload": payload})
    expected_tag = hmac.new(pivot2_key, auth_input, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(stored_tag, expected_tag):
        raise ValueError("Authentication failed: metadata does not validate "
                         "(wrong key or tampered ciphertext)")

    # --- Reverse the structural transform ---------------------------------
    permutation = meta["permutation"]
    original_keys = meta["original_keys"]
    reordered_keys = [original_keys[i] for i in permutation]

    # Rebuild in original field order.
    restored = {}
    for original_index in range(meta["field_count"]):
        name = original_keys[original_index]
        restored[name] = payload[name]

    # ``reordered_keys`` is retained above for clarity/debugging; the restore
    # itself only needs original_keys, since payload is keyed by field name.
    del reordered_keys
    return restored


# ---------------------------------------------------------------------------
# Canonical serialization (used for authentication)
# ---------------------------------------------------------------------------


def _canonical_bytes(obj) -> bytes:
    """Serialize ``obj`` deterministically for HMAC computation.

    ``sort_keys=True`` guarantees the same byte string on both encrypt and
    decrypt regardless of dict ordering, which is essential for the auth tag
    to match.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


def double_pivot_encrypt(plaintext_obj: dict, master_key: bytes) -> bytes:
    """Encrypt (structurally transform) a dict into intermediate ciphertext.

    Derives both pivot keys from ``master_key`` and applies Pivot 1.
    """
    pivot1_key = kdf(master_key, context="structural")
    pivot2_key = kdf(master_key, context="interpretive")
    return pivot1_structural_transform(plaintext_obj, pivot1_key, pivot2_key)


def double_pivot_decrypt(ciphertext: bytes, master_key: bytes) -> dict:
    """Decrypt (structurally restore) intermediate ciphertext back into a dict.

    Derives ``pivot2_key`` from ``master_key`` and applies Pivot 2, which both
    validates authenticity and reverses the structural transform.
    """
    pivot2_key = kdf(master_key, context="interpretive")
    return pivot2_interpretive_transform(ciphertext, pivot2_key)


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

    # Tamper / wrong-key check: decrypting with a different master key must fail
    # the Pivot 2 authentication step.
    try:
        double_pivot_decrypt(ciphertext, b"wrong-master-key")
    except ValueError as exc:
        print(f"OK: authentication correctly rejected wrong key ({exc})")
    else:
        raise AssertionError("Expected authentication failure with wrong key")
