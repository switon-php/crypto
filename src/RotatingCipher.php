<?php

declare(strict_types=1);

namespace Switon\Crypto;

use Switon\Core\Attribute\Autowired;
use Switon\Crypto\Exception\MissingDecryptRuleException;

/**
 * Rotation-aware cipher for CipherInterface bindings that must read legacy ciphertext.
 *
 * Use when new writes should use the current cipher but old ciphertext may still exist in storage.
 * Guidance: Pass a field-specific decrypt rule because broad text checks reduce confidence during rotation.
 *
 * Configure with:
 * - <code>$newCipher</code>: cipher used for all new writes and the first decrypt attempt
 * - <code>$legacyCipher</code>: fallback reader for old ciphertext
 *
 * Road-signs:
 * - Bind this behind <code>CipherInterface</code> during migration windows
 * - Pass a field-appropriate decrypt rule such as <code>json</code> or <code>uuid</code>
 * - Remove <code>$legacyCipher</code> after old ciphertext is gone
 * - legacy fallback is attempted only after new-cipher decrypt throws <code>\Switon\Crypto\Exception</code>
 *
 * @see \Switon\Crypto\CipherInterface
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\ValidatorInterface
 * @see \Switon\Crypto\Exception\ValidationFailedException
 * @see \Switon\Crypto\Exception\MissingDecryptRuleException
 */
class RotatingCipher implements CipherInterface
{
    #[Autowired] protected CipherInterface $newCipher;

    #[Autowired] protected CipherInterface $legacyCipher;

    /** {@inheritDoc} */
    public function encrypt(string $text, string $key): string
    {
        return $this->newCipher->encrypt($text, $key);
    }

    /**
     * {@inheritDoc}
     *
     * @throws MissingDecryptRuleException When <code>$rule</code> is <code>null</code> (rotation requires a validation rule on the new-cipher path)
     *
     * New-cipher decrypt uses the caller-provided rule. If that path throws <code>\Switon\Crypto\Exception</code>,
     * legacy fallback calls <code>$legacyCipher->decrypt($text, $key)</code> without re-applying the same rule.
     */
    public function decrypt(string $text, string $key, mixed $rule = null): string
    {
        if ($rule === null) {
            MissingDecryptRuleException::raise(
                'RotatingCipher::decrypt() requires a non-null validation rule. Pass a built-in rule, a ?-prefixed rule, or a callable; use Cipher without rotation when skipping validation.'
            );
        }

        try {
            return $this->newCipher->decrypt($text, $key, $rule);
        } catch (Exception) {
            return $this->legacyCipher->decrypt($text, $key);
        }
    }

    /** {@inheritDoc} */
    public function getDerivedKey(string $type, int $bits): string
    {
        return $this->newCipher->getDerivedKey($type, $bits);
    }

}
