# predicate-receipt

`predicate-receipt` is a small, fail-closed Rust CLI for checking JSON produced
by agents, generators, or automation before another system consumes it. It
evaluates a versioned set of hard predicates and emits a deterministic receipt
that binds the policy, candidate, and every rule result with SHA-256 digests.

It is deliberately narrower than a general policy engine. It does not infer
requirements, grant authority, execute the candidate, or claim that passing
syntactic predicates makes an action safe.

## What works

- RFC 6901 JSON Pointer selection
- required and forbidden values
- exact equality and allowlists
- inclusive numeric bounds
- Unicode string-length and regex checks
- array-length bounds
- complete results without short-circuiting
- canonical JSON hashing, insensitive to whitespace and object key order
- exact receipt re-verification against the original policy and candidate
- distinct exit codes: `0` allow, `2` deny, `1` malformed input or tool error

## Install

```bash
cargo install --git https://github.com/nicholas-ruest/predicate-receipt
```

Or build from a clone with stable Rust:

```bash
cargo build --release
```

## Use

Evaluate the included allowed example and retain its receipt:

```bash
cargo run -- check \
  --policy examples/transfer-policy.json \
  --input examples/allowed-transfer.json \
  --receipt transfer.receipt.json
```

Recompute the result and verify that the receipt still matches exactly:

```bash
cargo run -- verify \
  --policy examples/transfer-policy.json \
  --input examples/allowed-transfer.json \
  --receipt transfer.receipt.json
```

A policy is ordinary JSON. Each rule has a stable ID, a JSON Pointer, and one
check:

```json
{
  "version": "transfer-v1",
  "rules": [
    {
      "id": "bounded_amount",
      "pointer": "/amount",
      "check": { "type": "number_range", "min": 0.01, "max": 5000.0 }
    },
    {
      "id": "no_admin_override",
      "pointer": "/admin_override",
      "check": { "type": "absent" }
    }
  ]
}
```

Supported check types are `exists`, `absent`, `equals`, `one_of`,
`number_range`, `string_length`, `string_pattern`, and `array_length`. Policy
files reject unknown fields, duplicate rule IDs, invalid pointers, empty
allowlists, invalid regular expressions, missing range bounds, and inverted
bounds.

## Verification

The repository's CI runs the same required stable-Rust gates:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Security model and limitations

Receipts are tamper-evident relative to a fresh local evaluation, not digitally
signed. Protect receipt storage or add an external signature if provenance
across trust boundaries matters. Numeric ranges use finite `f64` values and are
not suitable for exact decimal accounting. Regex checks use Rust's linear-time
regex engine. Predicate evaluation proves only the checks explicitly expressed
in the supplied policy over the supplied JSON.

## License

MIT
