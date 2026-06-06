<?php

declare(strict_types=1);

namespace Switon\Crypto\Command;

use Switon\Core\Attribute\Autowired;
use Switon\Core\ConsoleInterface;
use Switon\Core\RandomInterface;

use function strtolower;

/**
 * Generate random keys for application secrets.
 *
 * @see \Switon\Core\RandomInterface Entropy source
 * @see \Switon\Core\ConsoleInterface Output boundary
 */
class KeyCommand
{
    #[Autowired] protected ConsoleInterface $console;
    #[Autowired] protected RandomInterface $random;

    /**
     * Generate a random key.
     *
     * @param int $length Key length in characters
     * @param bool $lowercase Output lowercase when true
     */
    public function generateAction(int $length = 32, bool $lowercase = false): void
    {
        $key = $this->random->chars($length);
        $this->console->writeLn($lowercase ? strtolower($key) : $key);
    }
}
