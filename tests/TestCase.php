<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Switon\Di\Container as DiContainer;
use Switon\Di\ServiceProvider as DiServiceProvider;

/**
 * Base test case for Crypto tests.
 *
 * Builds a minimal DI container for cipher tests — no full app provider scan.
 */
abstract class TestCase extends BaseTestCase
{
    protected DiContainer $container;

    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new DiContainer();
        $diProvider = new DiServiceProvider();
        $diProvider->register($this->container);
        $diProvider->boot();
    }
}
