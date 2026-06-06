<?php

declare(strict_types=1);

namespace Switon\Crypto;

use function base64_decode;
use function base64_encode;
use function filter_var;
use function json_validate;
use function mb_check_encoding;
use function ord;
use function preg_match;
use function strlen;

use const FILTER_VALIDATE_EMAIL;

/**
 * Default validator for common crypto plaintext rules.
 *
 * Use when decrypt callers need built-in rule names such as <code>json</code>, <code>uuid</code>, or <code>?email</code>.
 * Guidance: Keep built-in rules structural and push business-specific semantics into callables.
 *
 * Road-signs:
 * - <code>validate()</code> handles built-in rule names and callables
 * - <code>?rule</code> short-circuits empty string values before base validation
 * - Empty string values otherwise pass only rules whose own predicate accepts them
 * - <code>Cipher::decrypt()</code> converts a false result into <code>ValidationFailedException</code>
 * - invalid rule declarations raise <code>Exception</code> instead of returning false
 *
 * @see \Switon\Crypto\ValidatorInterface
 * @see \Switon\Crypto\Cipher::decrypt()
 * @see \Switon\Crypto\Exception\ValidationFailedException
 */
class Validator implements ValidatorInterface
{
    /** {@inheritDoc} */
    public function validate(string $value, mixed $rule): bool
    {
        if (is_string($rule)) {
            if ($rule !== '' && $rule[0] === '?') {
                if ($value === '') {
                    if ($rule === '?') {
                        Exception::raise(
                            'Invalid validator rule "{rule}". Use: ascii, utf8, json, numeric, base64, uuid, email, ?rule, or a callable.',
                            ['rule' => $rule]
                        );
                    }

                    return true;
                }

                $rule = substr($rule, 1);
            }

            return match ($rule) {
                'ascii' => $this->isAscii($value),
                'utf8' => $this->isUtf8($value),
                'json' => $this->isJson($value),
                'numeric' => $this->isNumeric($value),
                'base64' => $this->isBase64($value),
                'uuid' => $this->isUuid($value),
                'email' => $this->isEmail($value),
                default => Exception::raise(
                    'Invalid validator rule "{rule}". Use: ascii, utf8, json, numeric, base64, uuid, email, ?rule, or a callable.',
                    ['rule' => $rule]
                ),
            };
        }

        if (!is_callable($rule)) {
            Exception::raise(
                'Invalid validator rule "{rule}". Use: ascii, utf8, json, numeric, base64, uuid, email, ?rule, or a callable.',
                ['rule' => get_debug_type($rule)]
            );
        }

        return (bool)$rule($value);
    }

    /**
     * Returns true when value contains only printable ASCII and allowed whitespace.
     */
    protected function isAscii(string $value): bool
    {
        $length = strlen($value);

        for ($i = 0; $i < $length; $i++) {
            $ord = ord($value[$i]);

            if ($ord > 127) {
                return false;
            }

            if (($ord >= 32 && $ord <= 126) || $ord === 9 || $ord === 10 || $ord === 13) {
                continue;
            }

            return false;
        }

        return true;
    }

    /**
     * Returns true when value is valid UTF-8 and contains no disallowed ASCII control characters.
     */
    protected function isUtf8(string $value): bool
    {
        if ($value === '') {
            return true;
        }

        if (!mb_check_encoding($value, 'UTF-8')) {
            return false;
        }

        $length = strlen($value);

        for ($i = 0; $i < $length; $i++) {
            $ord = ord($value[$i]);

            if ($ord >= 128) {
                continue;
            }

            if (($ord >= 32 && $ord <= 126) || $ord === 9 || $ord === 10 || $ord === 13) {
                continue;
            }

            return false;
        }

        return true;
    }

    /**
     * Returns true when value is valid JSON.
     */
    protected function isJson(string $value): bool
    {
        return json_validate($value);
    }

    /**
     * Returns true when value contains only decimal digits.
     */
    protected function isNumeric(string $value): bool
    {
        return $value !== '' && preg_match('/^\d+$/', $value) === 1;
    }

    /**
     * Returns true when value is canonical base64.
     */
    protected function isBase64(string $value): bool
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $value) !== 1 || strlen($value) % 4 !== 0) {
            return false;
        }

        return base64_encode(base64_decode($value, true)) === $value;
    }

    /**
     * Returns true when value is a canonical UUID string.
     */
    protected function isUuid(string $value): bool
    {
        return preg_match(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $value
        ) === 1;
    }

    /**
     * Returns true when value is a valid email address.
     */
    protected function isEmail(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }
}
