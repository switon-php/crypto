<?php

declare(strict_types=1);

namespace Switon\Crypto\Exception;

use Switon\Crypto\Exception;

/**
 * Derived key mode requires non-empty secret configuration.
 *
 * @see \Switon\Crypto\Exception
 */
class MissingSecretException extends Exception
{
}
