"""Cryptographic verification tests using ephemeral in-memory keys."""

import base64
import copy
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuity_verify import METHOD, VerificationError, canonical_payload, verify_record


ROOT = Path(__file__).resolve().parents[1]


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / "continuity-record.json").read_text(encoding="utf-8"))
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.record["proof"] = {
            "status": "signed",
            "reason": "Ephemeral test fixture; no key is stored.",
            "method": METHOD,
            "verification_method": "urn:ed25519:" + b64url(public_key),
        }
        self.record["proof"]["signature"] = b64url(
            self.private_key.sign(canonical_payload(self.record))
        )

    def assert_verification_fails(self, record):
        with self.assertRaises(VerificationError):
            verify_record(record)

    def test_valid_signature_passes(self):
        verify_record(self.record)

    def test_changed_claim_fails(self):
        changed = copy.deepcopy(self.record)
        changed["claim"]["statement"] += " Altered."
        self.assert_verification_fails(changed)

    def test_changed_identifier_fails(self):
        changed = copy.deepcopy(self.record)
        changed["identifiers"][0]["handle"] = "AICID-0000-0000-0000-0000"
        self.assert_verification_fails(changed)

    def test_changed_proof_reason_fails(self):
        changed = copy.deepcopy(self.record)
        changed["proof"]["reason"] = "Altered reason."
        self.assert_verification_fails(changed)

    def test_changed_signature_fails(self):
        changed = copy.deepcopy(self.record)
        raw = bytearray(base64.urlsafe_b64decode(changed["proof"]["signature"] + "=="))
        raw[0] ^= 1
        changed["proof"]["signature"] = b64url(bytes(raw))
        self.assert_verification_fails(changed)

    def test_unsupported_method_fails(self):
        changed = copy.deepcopy(self.record)
        changed["proof"]["method"] = "SomethingElse"
        self.assert_verification_fails(changed)

    def test_malformed_public_key_fails(self):
        changed = copy.deepcopy(self.record)
        changed["proof"]["verification_method"] = "urn:ed25519:not-a-key"
        self.assert_verification_fails(changed)

    def test_padded_signature_fails(self):
        changed = copy.deepcopy(self.record)
        changed["proof"]["signature"] += "=="
        self.assert_verification_fails(changed)

    def test_unsigned_record_fails(self):
        unsigned = json.loads((ROOT / "continuity-record.json").read_text(encoding="utf-8"))
        self.assert_verification_fails(unsigned)


if __name__ == "__main__":
    unittest.main()
