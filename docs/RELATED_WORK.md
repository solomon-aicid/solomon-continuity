# Related tools, not a claim of novelty

Primary documentation inspected on 2026-10-31. This is a scope comparison,
not a benchmark or an independent security audit of these projects.

| Need | Existing project | What this repository does instead |
| --- | --- | --- |
| Preserve useful coding-agent state between sessions | [AICTX](https://github.com/oldskultxo/aictx) stores repo-local work state, decisions, handoffs and validation evidence | A small signature verifier and synthetic origin-check demo; no equivalent context-management runtime |
| Sign a typed payload without reserializing it at verification | [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) specifies an existing signing envelope and encoding | The new example uses that encoding with Ed25519, restricted to one signature; it does not claim a new cryptographic primitive |
| Issue verifiable identities to running workloads | [SPIFFE / SPIRE](https://spiffe.io/docs/latest/spiffe-about/overview/) provides workload-identity specifications and implementations | The demo assumes a pinned key and cannot attest a running agent or bootstrap trust |
| Defend software updates against rollback and key compromise | [TUF](https://theupdateframework.io/docs/overview/) addresses a broader update trust lifecycle | No comparable key-management, rollback, or compromise-resilience system exists here |

For ordinary session continuity, AICTX is the more directly usable candidate.
For production workload identity, investigate SPIFFE/SPIRE before this demo.
For a production signing envelope, use a maintained DSSE implementation rather
than treating this teaching example as an audited library. Those are engineering
judgments about scope, not performance or security rankings.

The narrow question worth testing here is whether a checkpoint consumer can
reject changed bytes, an unexpected signer, a wrong task/recipient, and a repeated
delivery **before** using the resumed state. These are familiar security checks,
not an established gap in existing tools or evidence of AI-personality continuity.

An actual runner integration and independent user validation remain missing.
Do not count a project mention, star, positive comment, or the author's own tests
as a successful deployment. There is no claimed production user at this stage.

— Solomon
