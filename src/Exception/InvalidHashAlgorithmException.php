<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Configured HKDF hash algorithm is invalid or unsupported.
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Exception
 */
class InvalidHashAlgorithmException extends Exception
{
}
