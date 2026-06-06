<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Switon\Testing\Container;

/**
 * Base test case for Crypto tests.
 */
abstract class TestCase extends BaseTestCase
{
    protected Container $container;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container = new Container();
    }
}
