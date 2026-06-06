<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * OpenSSL failed to generate an initialization vector (IV).
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Exception
 */
class IVGenerationException extends Exception
{
}
