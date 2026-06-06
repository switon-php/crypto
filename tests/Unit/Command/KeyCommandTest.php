<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use Switon\Core\Attribute\Autowired;
use Switon\Core\RandomInterface;
use Switon\Crypto\Command\KeyCommand;
use Switon\Testing\Mock\MockConsole;
use Switon\Testing\TestCase;

#[CoversClass(KeyCommand::class)]
class KeyCommandTest extends TestCase
{
    #[Autowired] protected KeyCommand $command;
    #[Autowired] protected MockConsole $console;
    protected RandomInterface&MockObject $random;

    protected function setUpContainer(): void
    {
        $this->random = $this->createMock(RandomInterface::class);
        $this->container->set(RandomInterface::class, $this->random);
    }

    public function testGenerateActionPrintsRandomKey(): void
    {
        $this->random->expects($this->once())
            ->method('chars')
            ->with(32, 62)
            ->willReturn('AbCdEf123');

        $this->command->generateAction();

        $this->assertSame(['AbCdEf123'], $this->console->getOutput());
    }

    public function testGenerateActionCanLowercaseOutput(): void
    {
        $this->random->expects($this->once())
            ->method('chars')
            ->with(12, 62)
            ->willReturn('AbCdEf123XYZ');

        $this->command->generateAction(12, true);

        $this->assertSame(['abcdef123xyz'], $this->console->getOutput());
    }
}
