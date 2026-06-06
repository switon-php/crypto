<?php

declare(strict_types=1);

namespace Switon\Crypto;

/**
 * Base exception for crypto operation failures.
 *
 * Use this as the parent for encryption, decryption, key-derivation, and validation failures.
 *
 * @see \Switon\Crypto\Exception\DecryptionFailedException
 * @see \Switon\Core\Exception
 */
class Exception extends \Switon\Core\Exception
{
}
