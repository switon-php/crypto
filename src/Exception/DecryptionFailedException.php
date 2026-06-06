<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Ciphertext cannot be decrypted with the provided method/key.
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Exception
 */
class DecryptionFailedException extends Exception
{
}
