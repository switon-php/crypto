# Switon Crypto Package

[![CI](https://img.shields.io/github/actions/workflow/status/switon-php/crypto/ci.yml?branch=main&label=CI)](https://github.com/switon-php/crypto/actions/workflows/ci.yml) [![PHP 8.3+](https://img.shields.io/badge/PHP-8.3%2B-777BB4)](https://www.php.net/)

Symmetric encryption, derived keys, plaintext validation, and key rotation for Switon Framework.

## Highlights

- **One encryption contract:** `CipherInterface` keeps app code on one reversible boundary.
- **Plaintext validation:** `ValidatorInterface` checks decrypted text before acceptance.
- **Rotation support:** `RotatingCipher` keeps legacy ciphertext readable during migration windows.
- **Key generation:** `KeyCommand` prints fresh application keys.

## Installation

```bash
composer require switon/crypto
```

## Quick Start

After you wire `CipherInterface` in `switon.yml`, inject it and use normal `encrypt()` / `decrypt()` calls.

```php
namespace App\Service;

use Switon\Core\Attribute\Autowired;
use Switon\Crypto\CipherInterface;

final class UserSecretService
{
    #[Autowired] protected CipherInterface $cipher;

    public function encryptProfile(string $payload): string
    {
        return $this->cipher->encrypt($payload, 'tenant:acme');
    }
}
```

Docs: https://docs.switon.dev/latest/crypto

## License

MIT.
