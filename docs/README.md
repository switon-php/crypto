# Crypto Package {#crypto-package}
`switon/crypto` standardizes reversible symmetric encryption, deterministic derived keys, structured plaintext validation, and key rotation for Switon apps. Choose it when application code should depend on one stable `CipherInterface` instead of scattered `openssl_*` calls.

**Key features:**

- **One encryption contract:** `Switon\Crypto\CipherInterface` keeps app code on one reversible boundary.
- **Key modes:** `mode` decides whether the per-call key is derived from the configured `secret` or treated as raw lowercase-hex bytes.
- **Plaintext validation:** `Switon\Crypto\ValidatorInterface` checks decrypted text with built-in rules or callables before it leaves `decrypt()`.
- **Rotation support:** `Switon\Crypto\RotatingCipher` keeps old ciphertext readable while new writes use the current cipher.
- **Deterministic derived keys:** `getDerivedKey()` returns repeatable lowercase-hex key material for other components.
- **Key generation command:** `bash bin/console key:generate` prints fresh secrets for new app deployments.

## Installation {#installation}

**Requirements:** PHP 8.3+, `ext-openssl`, `ext-mbstring`

```bash
composer require switon/crypto
```

## Quick Start {#quick-start}

Configure one `secret` in `derived` mode, inject `CipherInterface`, and pass a validation rule whenever the plaintext has a known shape.

```yaml
# switon.yml
Switon\Crypto\CipherInterface:
  secret: '<master-secret>'
  mode: derived
```

```php
namespace App\Service;

use Switon\Core\Attribute\Autowired;
use Switon\Crypto\CipherInterface;

final class UserSecretService
{
    #[Autowired] protected CipherInterface $cipher;

    public function encryptProfile(int $userId, array $profile): string
    {
        return $this->cipher->encrypt(
            json_encode($profile, JSON_THROW_ON_ERROR),
            "user:{$userId}"
        );
    }

    public function decryptProfile(int $userId, string $payload): array
    {
        $json = $this->cipher->decrypt($payload, "user:{$userId}", 'json');

        return json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    }
}
```

The encrypted payload is binary (`[IV][ciphertext]`, or `[IV][ciphertext][tag]` for AEAD methods). Base64-encode it only if your storage or transport cannot keep raw bytes.

To rotate keys during a migration window, bind `RotatingCipher` behind the interface with separate `newCipher` and `legacyCipher` slots:

```yaml
# switon.yml
Switon\Crypto\CipherInterface:
  class: Switon\Crypto\RotatingCipher
  newCipher:
    class: Switon\Crypto\Cipher
    secret: '<current-secret>'
    mode: derived
  legacyCipher:
    class: Switon\Crypto\Cipher
    secret: '<legacy-secret>'
    mode: raw
```

## Core Concepts {#core-concepts}

### Key modes {#key-modes}

`Switon\Crypto\Cipher` interprets the per-call `$key` argument according to its configured `mode`:

- `derived` — always derives a binary key from `secret` plus the caller-supplied key material. Recommended for new apps.
- `raw` — treats `$key` as a real lowercase-hex secret (length ≥ 32, multiple of 16) and skips derivation.
- `auto` — uses raw mode when the input matches the lowercase-hex shape; otherwise falls through to derivation.

`derived` mode requires a non-empty `secret`; otherwise `Switon\Crypto\Exception\MissingSecretException` is raised.

### Plaintext validation {#plaintext-validation}

`decrypt()` runs an optional rule against the decoded text before returning it. Built-in rules: `ascii`, `utf8`, `json`, `numeric`, `base64`, `uuid`, `email`. Prefix any built-in rule with `?` to allow an empty string (for example `?json`). A callable `fn(string $value): bool` works too. `null` skips validation but is **not** allowed on `RotatingCipher`.

### Key rotation {#key-rotation}

`Switon\Crypto\RotatingCipher` composes two ciphers for migration windows.

- New writes go through the new cipher only.
- `decrypt()` requires a non-null validation rule and tries the new cipher first.
- A `Switon\Crypto\Exception` from the new path triggers a fallback to the legacy cipher; non-crypto exceptions still bubble.
- Legacy fallback calls `legacyCipher->decrypt($text, $key)` without re-applying the rule, because the legacy format may pre-date the current shape.
- `getDerivedKey()` always uses the new cipher.

### Deterministic derived keys {#derived-keys}

`getDerivedKey(string $type, int $bits)` returns lowercase-hex key material. The same `$type` and `$bits` always yield the same key on a given `secret`, which is what other components (for example JWT signing keys) need for stable lookups. `$bits` must be a positive multiple of 8.

### Key generation {#key-generation}

`bash bin/console key:generate` prints a random character string for use as `secret`. The default is `RandomInterface::chars(32)`. Use `--length=<n>` to change the character count and `--lowercase` to lowercase the output.

## Configuration {#configuration}

```yaml
# switon.yml
Switon\Crypto\CipherInterface:
  secret: '<master-secret>'
  mode: derived
```

Touch `method` and `algo` only when matching an existing data store or a specific OpenSSL profile. The package does not freeze defaults in this doc; query them through option discovery.

### Option discovery {#option-discovery}

```bash
bash bin/console config:options 'Switon\Crypto\CipherInterface'
```

## Keep in Mind {#keep-in-mind}

- Use `derived` mode for normal app data; reserve `raw` for genuine lowercase-hex keys.
- Provide a validation rule whenever the plaintext has a known shape; on `RotatingCipher` a rule is required.
- The encrypted payload is binary. Encode it only if your transport or storage demands it.
- Remove `legacyCipher` after the old ciphertext is gone so rotation cannot mask new bugs.

## Next {#next}

- **For errors, rules, and rotation behavior:** [FAQ](faq.md#crypto-faq)
- **For trade-offs and rationale:** [Design Rationale](design.md#design-rationale)
