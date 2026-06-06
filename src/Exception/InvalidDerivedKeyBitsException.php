<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Derived key bit length is invalid for HKDF output.
 *
 * @see \Switon\Crypto\CipherInterface::getDerivedKey()
 * @see \Switon\Crypto\Cipher
 */
class InvalidDerivedKeyBitsException extends Exception
{
}
