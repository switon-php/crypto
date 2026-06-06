<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Use when \Switon\Crypto\RotatingCipher::decrypt() was called without a validation rule.
 *
 * @see \Switon\Crypto\RotatingCipher::decrypt()
 * @see \Switon\Crypto\RotatingCipher
 * @see \Switon\Crypto\CipherInterface::decrypt()
 */
class MissingDecryptRuleException extends Exception
{
}
