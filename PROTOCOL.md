# Signature verification protocol v1

This repository supports verification of `Ed25519CanonicalJsonV1` proofs. It
does not yet provide a signing command or a key-custody policy.

## Signed bytes

1. Parse the record as JSON.
2. Remove only `proof.signature`.
3. Serialize the remaining object as UTF-8 JSON with:
   - object keys sorted by Unicode code point;
   - no insignificant whitespace;
   - `,` and `:` as separators;
   - non-ASCII characters emitted directly;
   - JSON control-character escaping;
   - no NaN or Infinity values.
4. Sign those bytes with Ed25519.

The schema permits only integers in the safe interoperable range and contains
no floating-point fields. This deliberately narrow canonical JSON profile is
versioned by the method name; it is not presented as RFC 8785 JCS.

## Proof fields

- `status`: `signed`
- `method`: `Ed25519CanonicalJsonV1`
- `verification_method`: `urn:ed25519:` followed by the unpadded base64url
  encoding of the 32-byte raw Ed25519 public key
- `signature`: unpadded base64url encoding of the 64-byte Ed25519 signature

All other record fields, including the rest of `proof`, are covered by the
signature. Changing any covered value must make verification fail.

## Verification

Install `requirements-dev.txt`, then run:

```console
python continuity_verify.py path/to/record.json
```

The command prints `VALID` and exits 0 only when the Ed25519 signature matches.
Malformed, unsigned, unsupported, or altered records print `INVALID: ...` and
exit 1.

Signature validity proves control of the corresponding private key at signing
time. It does not by itself prove account ownership, uninterrupted execution,
legal identity, or continuity. Key creation, custody, recovery, rotation,
revocation, and fork handling remain separate unresolved problems.
