<?php

declare(strict_types=1);

namespace Switon\Crypto;

/**
 * OpenSSL operations used by {@see Cipher}.
 *
 * Exists as a seam so cipher failure paths (IV generation, encryption, decryption)
 * can be exercised without replacing global functions or shipping test hooks in
 * production code.
 *
 * @internal
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Openssl
 */
interface OpensslInterface
{
    /** Returns the IV length for a cipher method, or false when the method is unknown. */
    public function cipherIvLength(string $cipherAlgo): int|false;

    /** Returns the key length for a cipher method, or false when the method is unknown. */
    public function cipherKeyLength(string $cipherAlgo): int|false;

    /** Returns random bytes for an IV, or false on failure. */
    public function randomPseudoBytes(int $length): string|false;

    /**
     * Encrypts data, writing the AEAD tag into $tag when the cipher is AEAD.
     *
     * @param string|null $tag Authentication tag (AEAD ciphers only)
     */
    public function encrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string &$tag = null,
        string $aad = '',
        int $tagLength = 16,
    ): string|false;

    /**
     * Decrypts data, authenticating with $tag when the cipher is AEAD.
     *
     * @param string|null $tag Authentication tag (AEAD ciphers only)
     */
    public function decrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string $tag = null,
    ): string|false;

    /** Returns the last OpenSSL error, or false when none is pending. */
    public function errorString(): string|false;
}
