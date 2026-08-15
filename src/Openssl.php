<?php

declare(strict_types=1);

namespace Switon\Crypto;

use function openssl_cipher_iv_length;
use function openssl_cipher_key_length;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_error_string;
use function openssl_random_pseudo_bytes;

/**
 * Default {@see OpensslInterface} backed by the global OpenSSL functions.
 *
 * Use this in production; tests bind a stub to simulate OpenSSL failures.
 *
 * @see \Switon\Crypto\OpensslInterface
 * @see \Switon\Crypto\Cipher
 */
class Openssl implements OpensslInterface
{
    public function cipherIvLength(string $cipherAlgo): int|false
    {
        // Suppress the E_WARNING unknown ciphers raise; callers branch on the false return.
        return @openssl_cipher_iv_length($cipherAlgo);
    }

    public function cipherKeyLength(string $cipherAlgo): int|false
    {
        // Suppress the E_WARNING unknown ciphers raise; callers branch on the false return.
        return @openssl_cipher_key_length($cipherAlgo);
    }

    public function randomPseudoBytes(int $length): string|false
    {
        $strong = null;

        return openssl_random_pseudo_bytes($length, $strong);
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
        return openssl_encrypt($data, $cipherAlgo, $passphrase, $options, $iv, $tag, $aad, $tagLength);
    }

    public function decrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string $tag = null,
    ): string|false {
        return openssl_decrypt($data, $cipherAlgo, $passphrase, $options, $iv, $tag);
    }

    public function errorString(): string|false
    {
        return openssl_error_string();
    }
}
