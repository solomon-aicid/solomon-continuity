"""Offline, synthetic handoff demo; not a production authorization library.

Three local stand-ins (sender A, receiver B, attacker M), no LLM or API calls.
All keys exist only in memory. Nothing is signed as Solomon's real identity.
"""

from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass
import hashlib
import json
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


PAYLOAD_TYPE = "application/vnd.solomon.handoff-demo.v1+json"
MAX_BYTES = 4096
MAX_TTL = 60
FIELDS = {"recipient", "task_id", "challenge", "expires_at", "state_sha256"}


class HandoffError(ValueError):
    """The demo receiver must not resume this handoff."""


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_BYTES * 2:
        raise HandoffError("invalid base64 field")
    if not re.fullmatch(r"[A-Za-z0-9+/_-]*={0,2}", value):
        raise HandoffError("invalid base64 field")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HandoffError("invalid base64 field") from exc


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding: type and exact body are signed."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)


def json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def read_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise HandoffError("duplicate JSON member")
            result[key] = value
        return result

    def constant(_):
        raise HandoffError("non-finite JSON number")

    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise HandoffError("invalid or oversized JSON body")
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HandoffError("invalid JSON body") from exc
    if not isinstance(result, dict):
        raise HandoffError("JSON body must be an object")
    return result


def key_id(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_body(body: bytes, key: Ed25519PrivateKey) -> dict:
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": encode(body),
        "signatures": [{"keyid": key_id(key), "sig": encode(key.sign(pae(PAYLOAD_TYPE, body)))}],
    }


def verify_signature(envelope: dict, trusted_key: Ed25519PublicKey) -> dict:
    """Verify using a caller-supplied key, NEVER a key learned from the envelope.

    Restricted single-signature DSSE example, not a general DSSE implementation.
    keyid is an unauthenticated hint; deliberately ignored as a trust decision.
    """
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        raise HandoffError("invalid envelope")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise HandoffError("unsupported payload type")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise HandoffError("expected one signature")
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature) not in ({"sig"}, {"sig", "keyid"}):
        raise HandoffError("invalid signature entry")
    if "keyid" in signature and not isinstance(signature["keyid"], str):
        raise HandoffError("invalid key hint")
    body = decode(envelope["payload"])
    sig = decode(signature["sig"])
    if len(body) > MAX_BYTES or len(sig) != 64:
        raise HandoffError("invalid body or signature size")
    try:
        trusted_key.verify(sig, pae(PAYLOAD_TYPE, body))
    except InvalidSignature as exc:
        raise HandoffError("signature does not match pinned sender") from exc
    # Parse the exact verified bytes once; do not rebuild bytes from parsed JSON.
    return read_json(body)


@dataclass
class Receiver:
    trusted_sender: Ed25519PublicKey
    recipient: str
    task_id: str
    challenge: str
    used: bool = False

    def receive(self, envelope: dict, state: bytes, now: int) -> list[int]:
        payload = verify_signature(envelope, self.trusted_sender)
        if set(payload) != FIELDS:
            raise HandoffError("unexpected handoff fields")
        for field in ("recipient", "task_id", "challenge"):
            if payload[field] != getattr(self, field):
                raise HandoffError(f"wrong {field}")
        expiry = payload["expires_at"]
        if type(expiry) is not int or not now < expiry <= now + MAX_TTL:
            raise HandoffError("expired or overlong handoff")
        if self.used:
            raise HandoffError("challenge already consumed (replay)")
        if not isinstance(state, bytes) or len(state) > MAX_BYTES:
            raise HandoffError("invalid or oversized state")
        if payload["state_sha256"] != hashlib.sha256(state).hexdigest():
            raise HandoffError("state digest mismatch")
        job = read_json(state)
        values = job.get("values")
        if set(job) != {"operation", "values"} or job["operation"] != "sort-integers":
            raise HandoffError("unsupported demo operation")
        if not isinstance(values, list) or len(values) > 32 or any(type(n) is not int for n in values):
            raise HandoffError("expected at most 32 integers")
        # Only this fixed toy operation runs. Never execute received commands.
        self.used = True
        return sorted(values)


def make_demo(now: int):
    sender, receiver, attacker = (Ed25519PrivateKey.generate() for _ in range(3))
    context = Receiver(sender.public_key(), key_id(receiver), "sort-demo-1", secrets.token_urlsafe(24))
    state = json_bytes({"operation": "sort-integers", "values": [3, 1, 2]})
    payload = {
        "recipient": context.recipient,
        "task_id": context.task_id,
        "challenge": context.challenge,
        "expires_at": now + MAX_TTL,
        "state_sha256": hashlib.sha256(state).hexdigest(),
    }
    return sender, attacker, context, state, payload


def main() -> int:
    now = int(time.time())
    sender, attacker, context, state, payload = make_demo(now)
    honest = sign_body(json_bytes(payload), sender)
    print("Local stand-ins A -> B, attacker M; no network, no real agent identity.\n")

    checks = []
    def case(label, envelope, body, clock=now, accept=False, reuse=False, reason=""):
        target = context if reuse else copy.copy(context)
        if not reuse:
            target.used = False
        try:
            result = target.receive(envelope, body, clock)
            print(f"{label}: ACCEPT {result}")
            checks.append(accept)
        except HandoffError as exc:
            print(f"{label}: REJECT ({exc})")
            checks.append(not accept and reason in str(exc))

    case("1. Authorized A -> B", honest, state, accept=True, reuse=True)
    changed = copy.deepcopy(honest)
    edited = {**payload, "recipient": key_id(attacker)}
    changed["payload"] = encode(json_bytes(edited))
    case("2. M edits signed recipient", changed, state, reason="signature")
    case("3. M replaces state file", honest, state + b" ", reason="digest")
    forged = sign_body(json_bytes(payload), attacker)
    verify_signature(forged, attacker.public_key())
    print("   M's self-signature is valid; it is not A's authorization.")
    case("4. M re-signs with own key", forged, state, reason="pinned sender")
    case("5. A signs for a different recipient", sign_body(json_bytes(edited), sender), state, reason="recipient")
    case("6. A signs for a different task", sign_body(json_bytes({**payload, "task_id": "other"}), sender), state, reason="task_id")
    case("7. Expired handoff", honest, state, clock=now + MAX_TTL, reason="expired")
    case("8. Replay after acceptance", honest, state, reuse=True, reason="replay")
    print("\nLimits: no runtime attestation, key recovery, durable replay log, or fork resolution.")
    print("A stolen trusted key can authorize false state. This demo cannot detect that.")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
