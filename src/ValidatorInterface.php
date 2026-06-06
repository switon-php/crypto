<?php

declare(strict_types=1);

namespace Switon\Crypto;

/**
 * Validates decrypted plaintext against built-in or custom rules.
 *
 * Use when decrypt callers know the expected plaintext shape and need to reject structurally wrong values.
 * Guidance: Keep rules field-specific and structural; use a callable when built-in rules cannot describe the business format.
 *
 * Road-signs:
 * - Built-in rules cover common text, identifier, and encoded string formats
 * - Prefix a built-in rule with <code>?</code> to allow empty string values
 * - <code>Cipher::decrypt()</code> calls this service when a decrypt rule is provided
 * - <code>RotatingCipher</code> relies on these checks to decide legacy fallback
 * - false means structure mismatch; invalid rule definitions raise exceptions
 *
 * @see \Switon\Crypto\CipherInterface
 * @see \Switon\Crypto\RotatingCipher
 * @see \Switon\Crypto\Validator
 * @see \Switon\Crypto\Exception\ValidationFailedException
 */
interface ValidatorInterface
{
    /**
     * Returns true when value satisfies the provided rule.
     *
     * Built-in rules: <code>ascii</code>, <code>utf8</code>, <code>json</code>, <code>numeric</code>,
     * <code>base64</code>, <code>uuid</code>, <code>email</code>. Prefix a built-in rule with <code>?</code> to
     * allow empty string values. Custom rules may be provided as <code>fn(string $value): bool</code>.
     *
     * @throws \Switon\Crypto\Exception When the rule name or rule type is invalid
     */
    public function validate(string $value, mixed $rule): bool;
}
