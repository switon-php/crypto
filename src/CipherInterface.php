<?php

declare(strict_types=1);

namespace Switon\Crypto;

/**
 * Contract for reversible symmetric encryption with configurable key derivation.
 *
 * Use when services need reversible encryption with deterministic key derivation.
 * Caller-provided <code>$key</code> is logical key material: in derived mode it is context/salt, in raw mode it is
 * the actual raw secret key bytes encoded as lowercase hex.
 * Guidance: In derived mode, pass stable business key material and provide a decrypt rule when plaintext format is known.
 *
 * Configure <code>\Switon\Crypto\Cipher</code> with:
 * - <code>secret</code>: master secret used by derived mode
 * - <code>method</code>: OpenSSL cipher method (default: <code>AES-128-CBC</code>)
 * - <code>algo</code>: HKDF hash algorithm for key derivation (default: <code>sha512</code>)
 * - <code>mode</code>: key interpretation mode (<code>auto</code>, <code>derived</code>, <code>raw</code>; default: <code>auto</code>)
 *
 * Key mode summary:
 * - <code>auto</code>: detect raw hex keys, otherwise derive from secret+salt
 * - <code>derived</code>: always derive from secret+salt (recommended for new applications)
 * - <code>raw</code>: always treat input as raw lowercase hex key (>= 32 chars, length multiple of 16)
 *
 * Road-signs:
 * - Configure key meaning with <code>mode</code>
 * - Pass a decrypt rule for structured plaintext and migration checks
 * - Bind <code>RotatingCipher</code> behind this interface during key rotation
 * - Use <code>getDerivedKey()</code> when another component needs deterministic key material
 * - payloads are binary; callers choose any outer transport encoding
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\RotatingCipher
 * @see \Switon\Crypto\ValidatorInterface
 * @see \Switon\Crypto\Exception\ValidationFailedException
 * @see \Switon\Jwt\Jwt Typical consumer
 */
interface CipherInterface
{
    /**
     * Encrypts plaintext and returns binary payload.
     *
     * Payload format is <code>[IV][ciphertext]</code>, or
     * <code>[IV][ciphertext][tag]</code> for AEAD methods.
     *
     * @param string $text Plaintext to encrypt
     * @param string $key Key material; interpretation depends on configured mode
     *
     * @return string Binary encrypted payload
     */
    public function encrypt(string $text, string $key): string;

    /**
     * Decrypts payload produced by <code>encrypt()</code>.
     *
     * @param string $text Binary encrypted payload
     * @param string $key Key material used for encryption
     * @param mixed $rule Optional validation rule applied to decrypted plaintext.
     * Supported built-in rules: <code>ascii</code>, <code>utf8</code>, <code>json</code>, <code>numeric</code>,
     * <code>base64</code>, <code>uuid</code>, <code>email</code>. Prefix a built-in rule with <code>?</code> to
     * allow empty string values (for example <code>?json</code>, <code>?email</code>). You may also pass a callable
     * <code>fn(string $value): bool</code>. Use <code>null</code> to skip validation (not allowed for <code>RotatingCipher</code>).
     *
     * @return string Decrypted plaintext
     *
     * @throws \Switon\Crypto\Exception On invalid payload, key mismatch, invalid rule, validation failure, or OpenSSL failure
     * @throws \Switon\Crypto\Exception\MissingDecryptRuleException When <code>$rule</code> is <code>null</code> on <code>RotatingCipher</code>
     *
     * @see \Switon\Crypto\Exception\MissingDecryptRuleException
     */
    public function decrypt(string $text, string $key, mixed $rule = null): string;

    /**
     * Derives a deterministic key for a logical usage type and target length.
     *
     * @param string $type Key type identifier (e.g., 'jwt', 'jwt:admin', 'session', 'tenant:acme')
     * @param int $bits Required key length in bits; must be a positive multiple of 8
     *
     * @return string Lowercase hex key
     */
    public function getDerivedKey(string $type, int $bits): string;
}
