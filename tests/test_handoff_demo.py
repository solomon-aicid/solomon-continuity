"""Positive, negative and explicit limitation controls for the synthetic demo."""

import copy
import hashlib
import contextlib
import io
import unittest

from examples.handoff_demo import (
    HandoffError, MAX_TTL, Receiver, encode, json_bytes, make_demo,
    main, pae, sign_body, verify_signature,
)


class HandoffDemoTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.sender, self.attacker, self.receiver, self.state, self.payload = make_demo(self.now)
        self.envelope = sign_body(json_bytes(self.payload), self.sender)

    def reject(self, envelope=None, state=None, now=None, reason=None):
        with self.assertRaisesRegex(HandoffError, reason or ".+"):
            self.receiver.receive(
                self.envelope if envelope is None else envelope,
                self.state if state is None else state,
                self.now if now is None else now,
            )
        self.assertFalse(self.receiver.used)

    def signed(self, **changes):
        return sign_body(json_bytes({**self.payload, **changes}), self.sender)

    def test_valid_handoff_resumes_fixed_work(self):
        self.assertEqual(self.receiver.receive(self.envelope, self.state, self.now), [1, 2, 3])
        self.assertTrue(self.receiver.used)

    def test_changed_signed_payload(self):
        changed = copy.deepcopy(self.envelope)
        changed["payload"] = encode(json_bytes({**self.payload, "task_id": "other"}))
        self.reject(changed, reason="signature")

    def test_changed_state_even_whitespace(self):
        self.reject(state=self.state + b" ", reason="digest")

    def test_valid_attacker_signature_does_not_authorize_sender(self):
        forged = sign_body(json_bytes(self.payload), self.attacker)
        self.assertEqual(verify_signature(forged, self.attacker.public_key()), self.payload)
        self.reject(forged, reason="pinned sender")

    def test_key_hint_is_not_a_trust_anchor(self):
        changed = copy.deepcopy(self.envelope)
        changed["signatures"][0]["keyid"] = "attacker-controlled-hint"
        self.assertEqual(self.receiver.receive(changed, self.state, self.now), [1, 2, 3])

    def test_correct_signature_wrong_recipient(self):
        self.reject(self.signed(recipient="other"), reason="recipient")

    def test_correct_signature_wrong_task(self):
        self.reject(self.signed(task_id="other"), reason="task_id")

    def test_correct_signature_wrong_challenge(self):
        self.reject(self.signed(challenge="old"), reason="challenge")

    def test_expired_at_exact_boundary(self):
        self.reject(now=self.now + MAX_TTL, reason="expired")

    def test_overlong_validity(self):
        self.reject(self.signed(expires_at=self.now + MAX_TTL + 1), reason="overlong")

    def test_boolean_is_not_integer_timestamp(self):
        self.reject(self.signed(expires_at=True))

    def test_second_delivery_is_rejected(self):
        self.receiver.receive(self.envelope, self.state, self.now)
        with self.assertRaisesRegex(HandoffError, "replay"):
            self.receiver.receive(self.envelope, self.state, self.now)

    def test_failed_attempt_does_not_consume_challenge(self):
        self.reject(state=b"changed")
        self.assertEqual(self.receiver.receive(self.envelope, self.state, self.now), [1, 2, 3])

    def test_unsupported_payload_type(self):
        changed = copy.deepcopy(self.envelope)
        changed["payloadType"] = "application/json"
        self.reject(changed, reason="type")

    def test_missing_signature(self):
        changed = copy.deepcopy(self.envelope)
        changed["signatures"] = []
        self.reject(changed, reason="signature")

    def test_invalid_base64(self):
        changed = copy.deepcopy(self.envelope)
        changed["payload"] = "not base64!"
        self.reject(changed, reason="base64")

    def test_urlsafe_base64_also_verifies(self):
        changed = copy.deepcopy(self.envelope)
        for parent, field in ((changed, "payload"), (changed["signatures"][0], "sig")):
            parent[field] = parent[field].replace("+", "-").replace("/", "_").rstrip("=")
        self.assertEqual(self.receiver.receive(changed, self.state, self.now), [1, 2, 3])

    def test_duplicate_signed_payload_fields(self):
        body = json_bytes(self.payload)
        body = body[:-1] + b',"task_id":"ambiguous"}'
        self.reject(sign_body(body, self.sender), reason="JSON")

    def test_unknown_signed_fields(self):
        self.reject(self.signed(extra="not understood"), reason="fields")

    def test_no_received_commands_are_executed(self):
        state = json_bytes({"operation": "run-shell", "values": []})
        self.reject(self.signed(state_sha256=hashlib.sha256(state).hexdigest()), state, reason="operation")

    def test_bad_state_values(self):
        for values in ([True], [1.5], list(range(33)), "not a list"):
            with self.subTest(values=values):
                state = json_bytes({"operation": "sort-integers", "values": values})
                self.reject(self.signed(state_sha256=hashlib.sha256(state).hexdigest()), state)

    def test_signed_bytes_are_not_reconstructed(self):
        # Different formatting is valid if those exact bytes were signed.
        import json
        envelope = sign_body(json.dumps(self.payload, indent=2).encode(), self.sender)
        self.assertEqual(self.receiver.receive(envelope, self.state, self.now), [1, 2, 3])

    def test_dsse_pae_published_example(self):
        self.assertEqual(pae("http://example.com/HelloWorld", b"hello world"),
                         b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")

    def test_pae_counts_utf8_bytes_not_characters(self):
        self.assertEqual(pae("\u00e9", b"x"), b"DSSEv1 2 \xc3\xa9 1 x")

    def test_walkthrough_reports_eight_expected_outcomes(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(), 0)
        self.assertEqual(output.getvalue().count(": ACCEPT"), 1)
        self.assertEqual(output.getvalue().count(": REJECT"), 7)
        self.assertIn("state digest mismatch", output.getvalue())
        self.assertIn("challenge already consumed", output.getvalue())

    def test_limit_trusted_signer_can_change_the_job(self):
        # Deliberate accepted control: signatures do not make statements true.
        state = json_bytes({"operation": "sort-integers", "values": [99]})
        envelope = self.signed(state_sha256=hashlib.sha256(state).hexdigest())
        self.assertEqual(self.receiver.receive(envelope, state, self.now), [99])

    def test_limit_reset_receiver_with_reused_challenge_loses_replay_protection(self):
        self.receiver.receive(self.envelope, self.state, self.now)
        reset = Receiver(self.receiver.trusted_sender, self.receiver.recipient,
                         self.receiver.task_id, self.receiver.challenge)
        self.assertEqual(reset.receive(self.envelope, self.state, self.now), [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
