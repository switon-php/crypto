<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Configured OpenSSL cipher method is invalid or unsupported.
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Exception
 */
class InvalidCipherMethodException extends Exception
{
}
