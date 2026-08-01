# Design Rationale {#design-rationale}
`switon/crypto` keeps reversible encryption small, deterministic, and easy to rotate, so application code never reaches into `openssl_*` directly and migration windows do not require changing call sites.

## See also {#see-also}

- [Crypto Package](README.md) — usage, configuration, and the public contract
- [FAQ](faq.md#crypto-faq) — common questions and troubleshooting

---

## Core Problem {#core-problem}

Reversible encryption tends to drift in predictable ways:

- one service treats a caller string as the secret; another derives it from business context;
- another deployment needs to keep old ciphertext readable after a rotation;
- validation rules drift away from the data shape they should protect.

The framework needs one boundary that hides those decisions from call sites and surfaces them through configuration.

## Primary Goal {#primary-goal}

Standardize one `encrypt()` / `decrypt()` contract first, then layer key derivation, validation, and rotation on top.

- **Benefit:** application code stays on a single reversible boundary.
- **Benefit:** derived keys are deterministic, so storage, lookups, and JWT signing keys repeat across requests.
- **Benefit:** structured plaintext can be checked before it is accepted.

## Core Choice {#core-choice}

Each crypto call is a self-contained operation; configuration decides how the inputs are interpreted.

- **`mode`** decides how the per-call `$key` argument is interpreted (`auto`, `derived`, `raw`).
- **`ValidatorInterface`** sits between `decrypt()` and acceptance; it is configurable so apps can plug in domain-specific rules without subclassing.
- **`RotatingCipher`** composes two ciphers instead of introducing a handler tree; the model stays "new wins, legacy fallback" rather than a routing graph.
- **`getDerivedKey()`** is exposed on the contract because consumers (JWT, session signing, ...) need stable key material derived from the same `secret`.

## Trade-Off {#trade-off}

The package favors predictability over routing flexibility.

- **Benefit:** failures are easier to reason about; one cipher, one rule, one optional fallback.
- **Cost:** `switon/crypto` does not model a general KMS or public-key workflow, and per-destination handler trees stay out of scope.

## Deliberate Simplicity {#deliberate-simplicity}

Several boundaries are intentionally narrow.

- Derived output is lowercase hex so it can move through configs and logs as plain text.
- Built-in rules stay small (`ascii`, `utf8`, `json`, `numeric`, `base64`, `uuid`, `email`); anything else is a callable or a custom validator.
- `RotatingCipher` requires a non-null rule on `decrypt()` so fallback is never silent.
- Legacy fallback intentionally does not re-apply the same rule, because the legacy format may pre-date today's shape.
- Key generation lives in `Switon\Crypto\Command\KeyCommand` so operator workflows stay separate from runtime crypto code.

That separation keeps reversible encryption, migration, and operator tooling from collapsing into one shape with mixed concerns.
