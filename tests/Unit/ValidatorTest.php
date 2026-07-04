<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Switon\Crypto\Validator;

class ValidatorTest extends TestCase
{
    protected Validator $validator;

    protected function setUp(): void
    {
        $this->validator = new Validator();
    }

    public function testValidateAcceptsUtf8Rule(): void
    {
        $this->assertTrue($this->validator->validate('中文测试', 'utf8'));
    }

    public function testValidateUtf8AcceptsEmptyString(): void
    {
        $this->assertTrue($this->validator->validate('', 'utf8'));
    }

    public function testValidateUtf8RejectsInvalidEncoding(): void
    {
        $invalidUtf8 = "\xFF\xFE";

        $this->assertFalse($this->validator->validate($invalidUtf8, 'utf8'));
    }

    public function testValidateAcceptsAsciiRule(): void
    {
        $this->assertTrue($this->validator->validate("a\tb\n", 'ascii'));
    }

    public function testValidateAsciiRejectsNonAscii(): void
    {
        $this->assertFalse($this->validator->validate('é', 'ascii'));
    }

    public function testValidateAcceptsJsonRule(): void
    {
        $this->assertTrue($this->validator->validate('{"name":"John"}', 'json'));
    }

    public function testValidateJsonRejectsInvalidJson(): void
    {
        $this->assertFalse($this->validator->validate('{', 'json'));
    }

    public function testValidateAcceptsEmailRule(): void
    {
        $this->assertTrue($this->validator->validate('mark@example.com', 'email'));
    }

    public function testValidateEmailRejectsInvalidAddress(): void
    {
        $this->assertFalse($this->validator->validate('not-an-email', 'email'));
    }

    public function testValidateAcceptsNumericRule(): void
    {
        $this->assertTrue($this->validator->validate('42', 'numeric'));
    }

    public function testValidateNumericRejectsNonDigitsAndEmpty(): void
    {
        $this->assertFalse($this->validator->validate('12a', 'numeric'));
        $this->assertFalse($this->validator->validate('', 'numeric'));
    }

    public function testValidateAcceptsBase64Rule(): void
    {
        $this->assertTrue($this->validator->validate('SGVsbG8=', 'base64'));
    }

    public function testValidateBase64RejectsNonCanonical(): void
    {
        $this->assertFalse($this->validator->validate('SGVsbG8', 'base64'));
    }

    public function testValidateAcceptsUuidRule(): void
    {
        $this->assertTrue($this->validator->validate('550e8400-e29b-41d4-a716-446655440000', 'uuid'));
    }

    public function testValidateUuidRejectsInvalidVariant(): void
    {
        $this->assertFalse($this->validator->validate('550e8400-e29b-41d4-a716-44665544000g', 'uuid'));
    }

    public function testValidateAcceptsOptionalRuleForEmptyString(): void
    {
        $this->assertTrue($this->validator->validate('', '?email'));
    }

    public function testValidateOptionalRuleStillChecksNonEmptyValue(): void
    {
        $this->assertFalse($this->validator->validate('bad', '?email'));
    }

    public function testValidateAcceptsCallableRule(): void
    {
        $this->assertTrue($this->validator->validate('expected', static fn (string $value): bool => $value === 'expected'));
    }

    public function testValidateCallableRejectsOnFalse(): void
    {
        $this->assertFalse($this->validator->validate('x', static fn (string $value): bool => $value === 'y'));
    }

    public function testValidateRejectsInvalidRuleType(): void
    {
        $this->assertFalse($this->validator->validate('test', ['bad']));
    }

    public function testValidateRejectsUnknownBuiltInRuleString(): void
    {
        $this->assertFalse($this->validator->validate('test', 'xml'));
    }

    public function testBareQuestionMarkRuleRejectsNonEmptyValue(): void
    {
        $this->assertFalse($this->validator->validate('anything', '?'));
    }

    public function testBareQuestionMarkRejectsEmptyValue(): void
    {
        $this->assertFalse($this->validator->validate('', '?'));
    }

    public function testUtf8RejectsAsciiControlCharacter(): void
    {
        $this->assertFalse($this->validator->validate("line\x00break", 'utf8'));
    }

    public function testAsciiRejectsVerticalTab(): void
    {
        $this->assertFalse($this->validator->validate("\x0b", 'ascii'));
    }
}
