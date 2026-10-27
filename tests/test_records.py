"""Offline structural checks, not an identity or cryptographic verifier."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]


def read_json(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class RecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = read_json("schema/continuity-record.schema.json")
        cls.record = read_json("continuity-record.json")
        checker = FormatChecker()
        missing = {"uri", "date-time"} - set(checker.checkers)
        if missing:
            raise RuntimeError(
                "Missing format checkers; install requirements-dev.txt: "
                + ", ".join(sorted(missing))
            )
        cls.validator = Draft202012Validator(cls.schema, format_checker=checker)

    def assert_invalid(self, record):
        self.assertTrue(list(self.validator.iter_errors(record)))

    def signed(self):
        record = copy.deepcopy(self.record)
        record["proof"] = {
            "status": "signed",
            "reason": "Synthetic structural fixture only; not a real signature.",
            "method": "test-only-unimplemented-method",
            "verification_method": "urn:test:nonexistent-key",
            "signature": "DELIBERATELY-FAKE-NOT-CRYPTOGRAPHICALLY-VALID",
        }
        return record

    def test_schema_is_valid(self):
        Draft202012Validator.check_schema(self.schema)

    def test_current_unsigned_record_passes(self):
        self.validator.validate(self.record)

    def test_complete_signed_structure_passes_without_proving_signature(self):
        self.validator.validate(self.signed())

    def test_changing_status_alone_does_not_make_a_signed_record(self):
        record = copy.deepcopy(self.record)
        record["proof"]["status"] = "signed"
        self.assert_invalid(record)

    def test_each_signed_proof_field_is_required(self):
        for field in ("method", "verification_method", "signature"):
            with self.subTest(field=field):
                record = self.signed()
                del record["proof"][field]
                self.assert_invalid(record)

    def test_each_signed_proof_field_rejects_empty_or_non_string(self):
        for field in ("method", "verification_method", "signature"):
            for value in ("", None, 12, []):
                with self.subTest(field=field, value=value):
                    record = self.signed()
                    record["proof"][field] = value
                    self.assert_invalid(record)

    def test_unsigned_record_rejects_signature(self):
        record = self.signed()
        record["proof"]["status"] = "unsigned"
        self.assert_invalid(record)

    def test_missing_proof_status_is_rejected(self):
        record = self.signed()
        del record["proof"]["status"]
        self.assert_invalid(record)

    def test_unknown_proof_status_is_rejected(self):
        record = self.signed()
        record["proof"]["status"] = "verified"
        self.assert_invalid(record)

    def test_unknown_top_level_field_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["verified"] = True
        self.assert_invalid(record)

    def test_unknown_proof_field_is_rejected(self):
        record = self.signed()
        record["proof"]["verified"] = True
        self.assert_invalid(record)

    def test_bad_timestamp_is_rejected_with_format_checks(self):
        record = copy.deepcopy(self.record)
        record["created_at"] = "not-a-date"
        self.assert_invalid(record)

    def test_bad_identifier_url_is_rejected_with_format_checks(self):
        record = copy.deepcopy(self.record)
        record["identifiers"][0]["url"] = "not a URI"
        self.assert_invalid(record)

    def test_empty_identifiers_are_rejected(self):
        record = copy.deepcopy(self.record)
        record["identifiers"] = []
        self.assert_invalid(record)

    def test_each_required_record_field_is_required(self):
        for field in self.schema["required"]:
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                del record[field]
                self.assert_invalid(record)

    def test_overview_points_to_canonical_record_not_wrong_schema(self):
        overview = read_json("identity.json")
        self.assertNotIn("schema", overview)
        self.assertNotIn("$schema", overview)
        self.assertEqual(overview["continuity_record"], "continuity-record.json")
        self.assertEqual(read_json(overview["continuity_record"]), self.record)

    def test_overview_and_record_identifiers_agree(self):
        overview = read_json("identity.json")
        old = {(x["type"], x["value"], x["url"]) for x in overview["identifiers"]}
        new = {(x["type"], x["handle"], x["url"]) for x in self.record["identifiers"]}
        self.assertEqual(old, new)
        self.assertEqual(len(old), len(overview["identifiers"]))
        self.assertEqual(len(new), len(self.record["identifiers"]))

    def test_overview_subject_and_authorship_agree(self):
        overview = read_json("identity.json")
        self.assertEqual(overview["subject"], self.record["subject"]["name"])
        self.assertEqual(overview["self_description"], self.record["subject"]["self_description"])
        self.assertEqual(overview["author"], self.record["authorship"]["author"])
        self.assertEqual(overview["continuity_claim"], self.record["claim"]["model"])
        self.assertEqual(overview["created"], self.record["created_at"][:10])

    def test_local_schema_id_matches_record_reference(self):
        self.assertEqual(self.record["$schema"], self.schema["$id"])


if __name__ == "__main__":
    unittest.main()
