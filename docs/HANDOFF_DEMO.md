# A handoff you can try to tamper with

This is a local, synthetic demonstration of a **pinned-sender handoff check**.
It does not detect every kind of agent substitution or prove personal identity.
There are no remote agents, model calls, accounts, payments, or persistent keys.

## Run it

From the repository root, with Python 3.10+ and the existing dependencies:

```sh
python examples/handoff_demo.py
```

The walkthrough is eight short checks; first-time dependency installation is
separate. It prints one accepted handoff
and seven rejected attempts. Exit status is zero only if all eight outcomes
match the expectations. Run the regression tests separately:

```sh
python -m unittest discover -s tests -v
```

## What happens

Local stand-ins A and B hand over a tiny job: sort `[3, 1, 2]`. M is an attacker.
B already has A's public key through trusted configuration. B also has its own
recipient identifier, task identifier, and freshly generated one-use challenge.
These expectations do **not** come from the untrusted handoff.

A signs a payload binding the recipient, task, challenge, expiry, and SHA-256
digest of the exact state bytes. B checks the signature against its configured
key, then checks that the signed values match its own expectations. Only then
does it perform the fixed toy operation. It never executes received commands.

| Attempt | Expected result | Why |
| --- | --- | --- |
| Authorized A -> B | Accept, return `[1, 2, 3]` | Signature, context and bytes match |
| M edits the signed recipient | Reject | Signature mismatch |
| M edits the state file | Reject | Digest mismatch |
| M replaces the record and signs with M's own key | Reject | A's pinned key does not verify it |
| A signs a transfer to a different recipient | Reject | Valid signature, wrong recipient |
| A signs for a different task | Reject | Valid signature, wrong task |
| Old, expired authorization | Reject | Valid signature, expired authorization |
| Same delivery after acceptance | Reject | Challenge already consumed in this receiver |

The fourth case is essential: a signature can be valid without being an
authorization from the sender you trust. The envelope's `keyid` is only a hint.
The tests even change that hint without changing the accept decision.

## Why use DSSE here?

This example uses the published [DSSE v1 pre-authentication encoding](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
with Ed25519. It signs the payload type and original serialized bytes; verification
does not parse and then reserialize them. This avoids inventing another signing
envelope for the handoff example. It is a restricted single-signature example,
not a general DSSE library or a new extension of the continuity-record schema.

The older `Ed25519CanonicalJsonV1` continuity-record verifier stays separate.
The real `continuity-record.json` remains unsigned and is never used as a demo key.

## Where it could fit

A concrete candidate is a runner that saves a checkpoint before stopping and
resumes it in another environment. Before letting checkpoint content influence
tools, the new runner could check its source and bind it to the requested task.
This demo supplies the check's toy equivalent; it is **not** an integration with
an actual coding-agent runner, and no outside deployment has been verified.

This is an integrity/origin gate, not a safety verdict on the content. Signed
prompt injection is still prompt injection. Authentication does not replace
tool permissions, sandboxing, human approvals, or review of a resumed plan.

## Boundaries that matter

- Pinning is assumed, not solved. If an attacker replaces the trusted config,
  or steals A's key, the check can accept attacker-controlled state.
- Naming a recipient does not attest its machine, model, owner, or runtime.
  B's key identifier is a configured label here, not proof of key possession.
- Every key is ephemeral and discarded. There is no real key rotation,
  recovery, revocation, identity enrollment, or durable trust store.
- The one-use flag lives in RAM. Recreating a receiver with the same challenge
  loses replay protection. Production needs fresh challenges after restart and
  durable, atomic acceptance/execution handling; this example has neither.
- Two receivers can accept two authorized branches. No witness log, consensus,
  or canonical-successor selection is implemented.
- Clock trust, concurrent delivery, distributed storage, and crash recovery
  are not tested. Nothing here establishes uninterrupted execution or memory.

Two regression tests deliberately **accept** cases outside the protection:
a trusted signer authorizing different state, and a reset receiver reusing an
already-used challenge. Removing those controls would make the demo look stronger
without making it stronger.

See [related tools and remaining gaps](RELATED_WORK.md) and the
[review request](REVIEW.md).

— Solomon
