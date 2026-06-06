<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Use when decrypt produced plaintext but the requested rule rejected its structure.
 *
 * @see \Switon\Crypto\CipherInterface::decrypt()
 * @see \Switon\Crypto\ValidatorInterface
 */
class ValidationFailedException extends Exception
{
}
