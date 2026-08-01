# Crypto FAQ {#crypto-faq}
Short answers for setup, validation, and rotation issues.

> **Prerequisites:** [Crypto Package](README.md)

## Getting Started {#getting-started}

### How do I start using `switon/crypto`? {#start-using}

Inject `Switon\Crypto\CipherInterface` and call `encrypt()` and `decrypt()`. Configure one `secret` in `derived` mode first. See [Quick Start](README.md#quick-start).

### Should new apps use `derived`, `raw`, or `auto`? {#pick-mode}

Use `derived` for new data. Use `raw` only when the per-call `$key` is genuinely lowercase-hex bytes. `auto` is for bridging older key formats and falls through to derivation when the input is not lowercase hex.

### How do I generate a fresh key? {#generate-key}

Run `bash bin/console key:generate`. Use `--length=<n>` to change the character count and `--lowercase` for lowercase output.

## Configuration {#configuration}

### Why do I get `MissingSecretException`? {#missing-secret}

`derived` mode (and `auto` when the input is not raw hex) requires a non-empty `secret`. Set it in `switon.yml` or use `raw` mode only when you really have hex key bytes.

### How do I inspect the current options? {#inspect-options}

Run `bash bin/console config:options 'Switon\Crypto\CipherInterface'`.

### Which options matter first? {#important-options}

Start with `secret` and `mode`. Touch `method` and `algo` only when matching an existing store or a specific OpenSSL profile.

### How do I wire `RotatingCipher`? {#wire-rotating-cipher}

Bind `Switon\Crypto\RotatingCipher` as the `CipherInterface` implementation and provide both `newCipher` (current) and `legacyCipher` (old) sub-bindings. See [Key rotation](README.md#key-rotation).

## Validation {#validation}

### Which validation rules are built in? {#built-in-rules}

`ascii`, `utf8`, `json`, `numeric`, `base64`, `uuid`, `email`. Prefix any built-in rule with `?` to allow the empty string.

### Can I use my own rule? {#custom-rule}

Yes. Pass a callable `fn(string $value): bool`, or rebind `Switon\Crypto\ValidatorInterface` for app-wide rules.

### Why does `RotatingCipher::decrypt()` require a rule? {#rotation-rule}

The fallback path needs a way to judge the new-cipher output before deciding to retry with the legacy cipher. Use `Switon\Crypto\Cipher` directly when you really need to skip validation.

### Why can a validation failure still hit legacy fallback? {#validation-fallback}

`RotatingCipher` treats any `Switon\Crypto\Exception` from the new cipher as a rotation-path failure, including `ValidationFailedException`. That is deliberate: old ciphertext may legitimately fail today's rule.

## Troubleshooting {#troubleshooting}

### Why is decryption failing on short input? {#short-input}

The payload is shorter than the IV (and shorter than IV plus tag for AEAD methods). Confirm you are passing the full binary payload unchanged; base64 round-trips often drop bytes.

### What does `key:generate` output? {#key-generate-output}

A random character string from `RandomInterface::chars()`, not raw OpenSSL bytes. Add `--lowercase` for lowercase output.

### Why does a legacy payload still fail? {#legacy-failure}

Either both the new and legacy ciphers reject it, or the new path raised a non-crypto exception that bypasses fallback. Inspect the exception class first.

### How do I test crypto code? {#testing}

Stay on the `CipherInterface` contract in tests. Keep fixtures small and assert both round-trip and failure branches.
