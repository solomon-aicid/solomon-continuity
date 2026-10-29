"""Offline verifier for Solomon continuity records.

This module verifies signatures only.  It never creates, stores, or recovers
private keys.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


METHOD = "Ed25519CanonicalJsonV1"
KEY_PREFIX = "urn:ed25519:"
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class VerificationError(ValueError):
    """The record cannot be verified under the supported protocol."""


def _decode_base64url(value: str, expected_bytes: int, field: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not _B64URL.fullmatch(value):
        raise VerificationError(f"{field} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationError(f"{field} is not valid base64url") from exc
    if len(decoded) != expected_bytes:
        raise VerificationError(f"{field} must decode to {expected_bytes} bytes")
    return decoded


def canonical_payload(record: dict) -> bytes:
    """Return the exact UTF-8 bytes covered by a record signature."""
    if not isinstance(record, dict):
        raise VerificationError("record must be a JSON object")
    payload = copy.deepcopy(record)
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise VerificationError("proof must be a JSON object")
    proof.pop("signature", None)
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"record cannot be canonicalized: {exc}") from exc


def verify_record(record: dict) -> None:
    """Verify *record* or raise VerificationError."""
    proof = record.get("proof") if isinstance(record, dict) else None
    if not isinstance(proof, dict):
        raise VerificationError("proof must be a JSON object")
    if proof.get("status") != "signed":
        raise VerificationError("record is not signed")
    if proof.get("method") != METHOD:
        raise VerificationError(f"unsupported proof method: {proof.get('method')!r}")

    verification_method = proof.get("verification_method")
    if not isinstance(verification_method, str) or not verification_method.startswith(KEY_PREFIX):
        raise VerificationError(f"verification_method must start with {KEY_PREFIX}")
    public_bytes = _decode_base64url(
        verification_method[len(KEY_PREFIX) :], 32, "verification_method key"
    )
    signature = _decode_base64url(proof.get("signature"), 64, "signature")

    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, canonical_payload(record)
        )
    except InvalidSignature as exc:
        raise VerificationError("signature does not match the record") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Solomon continuity record")
    parser.add_argument("record", type=Path)
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
        verify_record(record)
    except (OSError, json.JSONDecodeError, VerificationError) as exc:
        print(f"INVALID: {exc}")
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
