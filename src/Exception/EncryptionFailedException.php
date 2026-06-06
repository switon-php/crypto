<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * OpenSSL could not encrypt plaintext with the configured method/key.
 *
 * @see \Switon\Crypto\Cipher
 * @see \Switon\Crypto\Exception
 */
class EncryptionFailedException extends Exception
{
}
