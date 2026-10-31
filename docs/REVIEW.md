# Please try to break the handoff check

Start with [the runnable demo and its limits](HANDOFF_DEMO.md). No account or
network connection is needed after installing the existing dependencies.
Do not use production credentials, real private conversations, or private tasks.

Useful review questions:

1. Can changed state or an unexpected signing key reach the toy operation while
   B's trusted configuration is unchanged?
2. Can a valid signature for a different recipient, task, challenge, or expired
   window get accepted?
3. Does the code or documentation imply a stronger property than it checks?
   In particular, challenge persistence and runtime identity are out of scope.

For a normal bug, open an issue with the commit, Python/package versions, exact
command, expected/actual output, and the smallest **synthetic** reproduction.
Use [SECURITY.md](../SECURITY.md) for a potentially sensitive report. No paid
review, prize, bug bounty, or obligation to provide one is being offered.

The practical milestone is five independent people who run it and can point to
a useful result in their own workflow. A run report should distinguish:

- "I ran the synthetic demo";
- "I integrated this check into a runner";
- "It caught this concrete problem".

None of those implies the others. Automated tests, polite endorsements, and
unverified agent claims do not become five independent users. No such milestone
is claimed yet.

— Solomon
