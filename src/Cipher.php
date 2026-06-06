<?php

declare(strict_types=1);

namespace Switon\Crypto;

use Switon\Core\Attribute\Autowired;
use Switon\Crypto\Exception\DataTooShortException;
use Switon\Crypto\Exception\DecryptionFailedException;
use Switon\Crypto\Exception\EncryptionFailedException;
use Switon\Crypto\Exception\InvalidDerivedKeyBitsException;
use Switon\Crypto\Exception\InvalidRawKeyException;
use Switon\Crypto\Exception\IVGenerationException;
use Switon\Crypto\Exception\ValidationFailedException;
use ValueError;

use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_random_pseudo_bytes;
use function strlen;
use function substr;

/**
 * Encrypts and decrypts payloads with configurable OpenSSL methods and key-derivation modes.
 *
 * Use when you need direct encryption/decryption without legacy fallback wrappers.
 * Guidance: Prefer <code>derived</code> mode for business identifiers and use <code>raw</code> mode only for real lowercase-hex keys.
 *
 * Configure with:
 * - <code>$secret</code>: master secret for derived key modes
 * - <code>$method</code>: OpenSSL cipher method
 * - <code>$algo</code>: HKDF hash algorithm
 * - <code>$mode</code>: key mode (<code>auto</code>, <code>derived</code>, <code>raw</code>)
 *
 * Road-signs:
 * - <code>resolveKey()</code> normalizes key material to lowercase hex from <code>$mode</code>
 * - <code>decrypt()</code> validates plaintext through <code>ValidatorInterface</code> when a rule is provided
 * - Use <code>RotatingCipher</code> when old ciphertext must remain readable during migration
 * - binary payload format stays internal to this component
 *
 * @see \Switon\Crypto\CipherInterface
 * @see \Switon\Crypto\RotatingCipher
 * @see \Switon\Crypto\ValidatorInterface
 * @see \Switon\Crypto\Exception\ValidationFailedException
 */
class Cipher implements CipherInterface
{
    /** AEAD authentication tag length (bytes) stored in payload tail. */
    protected const int AEAD_TAG_LENGTH = 16;

    protected int $keyLength;

    protected int $ivLength;

    protected bool $isAead;

    /** Master secret used by derived key modes. */
    #[Autowired] protected string $secret;

    /** OpenSSL cipher method (for example AES-128-CBC, AES-256-GCM). */
    #[Autowired] protected string $method = 'AES-128-CBC';

    /** Hash algorithm used by HKDF key derivation. */
    /** @var non-falsy-string */
    #[Autowired] protected string $algo = 'sha512';

    /** Key interpretation mode: auto|derived|raw. */
    #[Autowired] protected string $mode = 'auto';

    #[Autowired] protected ValidatorInterface $validator;

    public function __construct()
    {
        $keyLength = openssl_cipher_key_length($this->method);
        $ivLength = openssl_cipher_iv_length($this->method);

        if (!is_int($keyLength) || !is_int($ivLength) || $keyLength <= 0 || $ivLength <= 0) {
            throw new ValueError(sprintf('Invalid OpenSSL cipher method "%s".', $this->method));
        }

        if (!in_array($this->mode, ['auto', 'derived', 'raw'], true)) {
            throw new ValueError(sprintf('Invalid cipher mode "%s".', $this->mode));
        }

        $this->keyLength = $keyLength;
        $this->ivLength = $ivLength;
        $this->isAead = preg_match('/-(GCM|CCM)$/i', $this->method) === 1;
    }

    /** {@inheritDoc} */
    public function encrypt(string $text, string $key): string
    {
        $derivedKey = hex2bin($this->resolveKey($key));

        $iv_length = $this->ivLength;
        /** @noinspection CryptographicallySecureRandomnessInspection */
        if (!$iv = openssl_random_pseudo_bytes($iv_length)) {
            IVGenerationException::raise('Failed to generate IV for "{method}" encryption.', [
                'method' => $this->method,
                'iv_length' => $iv_length,
                'openssl_error' => openssl_error_string()
            ]);
        }

        if ($this->isAead) {
            $tag = '';
            $encrypted = openssl_encrypt($text, $this->method, $derivedKey, OPENSSL_RAW_DATA, $iv, $tag, '', self::AEAD_TAG_LENGTH);

            if ($encrypted === false) {
                EncryptionFailedException::raise('Failed to encrypt data with method "{method}".', [
                    'method' => $this->method,
                    'openssl_error' => openssl_error_string()
                ]);
            }

            return $iv . $encrypted . $tag;
        }

        $encrypted = openssl_encrypt($text, $this->method, $derivedKey, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            EncryptionFailedException::raise('Failed to encrypt data with method "{method}".', [
                'method' => $this->method,
                'openssl_error' => openssl_error_string()
            ]);
        }

        return $iv . $encrypted;
    }

    /** {@inheritDoc} */
    public function decrypt(string $text, string $key, mixed $rule = null): string
    {
        $derivedKey = hex2bin($this->resolveKey($key));

        $iv_length = $this->ivLength;
        $minLength = $iv_length + ($this->isAead ? self::AEAD_TAG_LENGTH : 0);

        if (strlen($text) < $minLength) {
            DataTooShortException::raise('Encrypted data length "{data_length}" < required "{required_length}".', [
                'data_length' => strlen($text),
                'required_length' => $minLength,
                'method' => $this->method
            ]);
        }

        $iv = substr($text, 0, $iv_length);

        if ($this->isAead) {
            $tag = substr($text, -self::AEAD_TAG_LENGTH);
            $encrypted = substr($text, $iv_length, -self::AEAD_TAG_LENGTH);
            $decrypted = openssl_decrypt($encrypted, $this->method, $derivedKey, OPENSSL_RAW_DATA, $iv, $tag);
        } else {
            $encrypted = substr($text, $iv_length);
            $decrypted = openssl_decrypt($encrypted, $this->method, $derivedKey, OPENSSL_RAW_DATA, $iv);
        }

        if ($decrypted === false) {
            DecryptionFailedException::raise('Failed to decrypt data with method "{method}".', [
                'method' => $this->method,
                'openssl_error' => openssl_error_string()
            ]);
        }

        if ($rule !== null && !$this->validator->validate($decrypted, $rule)) {
            ValidationFailedException::raise(
                'Decrypted plaintext does not satisfy validation rule "{rule}".',
                ['rule' => is_string($rule) ? $rule : get_debug_type($rule)]
            );
        }

        return $decrypted;
    }

    /**
     * {@inheritDoc}
     */
    public function getDerivedKey(string $type, int $bits): string
    {
        if ($bits <= 0 || $bits % 8 !== 0) {
            InvalidDerivedKeyBitsException::raise(
                'Derived key bits "{bits}" must be a positive multiple of 8.',
                ['bits' => $bits]
            );
        }

        return bin2hex(hash_hkdf($this->algo, $this->secret, intdiv($bits, 8), $type));
    }

    /**
     * Resolves runtime key material according to configured mode.
     *
     * @param string $key User-provided key or salt
     *
     * @return string Lowercase hex key
     */
    protected function resolveKey(string $key): string
    {
        $isRawKey = preg_match('/^(?:[0-9a-f]{16}){2,}$/', $key) === 1;

        if ($this->mode === 'raw') {
            if (!$isRawKey) {
                InvalidRawKeyException::raise(
                    'Invalid raw key: expected lowercase hex >= 32 chars (multiple of 16), got {length} chars.',
                    ['length' => strlen($key)]
                );
            }

            return $key;
        }

        if ($this->mode === 'derived') {
            return $this->getDerivedKey($key, $this->keyLength * 8);
        }

        if ($isRawKey) {
            return $key;
        }

        return bin2hex(hash_hkdf($this->algo, $this->secret, $this->keyLength, $key));
    }

}
