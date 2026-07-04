<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests\Fixtures;

use Switon\Crypto\OpensslInterface;

/**
 * Routes OpenSSL calls to the global functions, with switches that force failures.
 *
 * Replaces the namespace function overrides the package used to ship in src/: the
 * production code now depends on {@see OpensslInterface}, so tests only need to
 * substitute this stub.
 */
class FailingOpenssl implements OpensslInterface
{
    public bool $failRandomBytes = false;

    public bool $failEncrypt = false;

    public bool $failDecrypt = false;

    public function cipherIvLength(string $cipherAlgo): int|false
    {
        return \openssl_cipher_iv_length($cipherAlgo);
    }

    public function cipherKeyLength(string $cipherAlgo): int|false
    {
        return \openssl_cipher_key_length($cipherAlgo);
    }

    public function randomPseudoBytes(int $length): string|false
    {
        if ($this->failRandomBytes) {
            return false;
        }

        $strong = null;

        return \openssl_random_pseudo_bytes($length, $strong);
    }

    public function encrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string &$tag = null,
        string $aad = '',
        int $tagLength = 16,
    ): string|false {
        if ($this->failEncrypt) {
            return false;
        }

        return \openssl_encrypt($data, $cipherAlgo, $passphrase, $options, $iv, $tag, $aad, $tagLength);
    }

    public function decrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string $tag = null,
    ): string|false {
        if ($this->failDecrypt) {
            return false;
        }

        return \openssl_decrypt($data, $cipherAlgo, $passphrase, $options, $iv, $tag);
    }

    public function errorString(): string|false
    {
        return \openssl_error_string();
    }
}
