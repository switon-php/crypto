<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Encrypted payload is shorter than required IV/tag length.
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Exception
 */
class DataTooShortException extends Exception
{
}
