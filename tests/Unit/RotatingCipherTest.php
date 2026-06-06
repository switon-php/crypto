<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests\Unit;

use RuntimeException;
use Switon\Crypto\Cipher;
use Switon\Crypto\CipherInterface;
use Switon\Crypto\Exception;
use Switon\Crypto\Exception\DataTooShortException;
use Switon\Crypto\Exception\DecryptionFailedException;
use Switon\Crypto\Exception\MissingDecryptRuleException;
use Switon\Crypto\Exception\ValidationFailedException;
use Switon\Crypto\RotatingCipher;
use Switon\Crypto\Tests\TestCase;
use Switon\Crypto\Validator;
use Switon\Crypto\ValidatorInterface;

class RotatingCipherTest extends TestCase
{
    protected RotatingCipher $rotatingCipher;

    protected function setUp(): void
    {
        parent::setUp();

        $this->container->set(CipherInterface::class . '#newCipher', [
            'class' => Cipher::class,
            'secret' => 'new-secret-key',
            'method' => 'AES-128-CBC',
            'algo' => 'sha256',
        ]);
        $this->container->set(CipherInterface::class . '#legacyCipher', [
            'class' => Cipher::class,
            'secret' => 'old-secret-key',
            'method' => 'AES-128-CBC',
            'algo' => 'md5',
        ]);

        $this->rotatingCipher = $this->makeRotatingCipher();
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $data = 'test data';
        $salt = 'user:123';

        $encrypted = $this->rotatingCipher->encrypt($data, $salt);
        $decrypted = $this->rotatingCipher->decrypt($encrypted, $salt, 'utf8');

        $this->assertSame($data, $decrypted);
    }

    public function testDecryptLegacyCipherData(): void
    {
        $data = 'test data';
        $salt = 'user:123';
        $legacyCipher = $this->container->get(CipherInterface::class . '#legacyCipher');
        $encrypted = $legacyCipher->encrypt($data, $salt);

        $decrypted = $this->rotatingCipher->decrypt($encrypted, $salt, 'utf8');

        $this->assertSame($data, $decrypted);
    }

    public function testDecryptUtf8DataWithBuiltinUtf8Validator(): void
    {
        $data = '中文测试 emoji: 🔐';
        $salt = 'user:123';

        $encrypted = $this->rotatingCipher->encrypt($data, $salt);
        $decrypted = $this->rotatingCipher->decrypt($encrypted, $salt, 'utf8');

        $this->assertSame($data, $decrypted);
    }

    public function testJsonValidatorAcceptsJsonPayload(): void
    {
        $cipher = $this->makeRotatingCipher();
        $data = '{"name":"John","age":30}';
        $salt = 'user:123';

        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, 'json'));
    }

    public function testAsciiValidatorFailureFallsBackToLegacyCipher(): void
    {
        $sharedNewCipher = $this->container->make(Cipher::class, [
            'secret' => 'shared-secret-key',
            'method' => 'AES-128-CBC',
            'algo' => 'sha256',
            'validator' => new Validator(),
        ]);
        $sharedLegacyCipher = $this->container->make(Cipher::class, [
            'secret' => 'shared-secret-key',
            'method' => 'AES-128-CBC',
            'algo' => 'sha256',
            'validator' => new Validator(),
        ]);
        $cipher = $this->container->make(RotatingCipher::class, [
            'newCipher' => $sharedNewCipher,
            'legacyCipher' => $sharedLegacyCipher,
            'validator' => new Validator(),
        ]);
        $data = '中文';
        $salt = 'user:123';
        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, 'ascii'));
    }

    public function testNumericValidatorAcceptsDigitString(): void
    {
        $cipher = $this->makeRotatingCipher();
        $data = '1234567890';
        $salt = 'user:123';

        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, 'numeric'));
    }

    public function testBase64ValidatorAcceptsCanonicalBase64(): void
    {
        $cipher = $this->makeRotatingCipher();
        $data = 'SGVsbG8gV29ybGQ=';
        $salt = 'user:123';

        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, 'base64'));
    }

    public function testUuidValidatorAcceptsCanonicalUuid(): void
    {
        $cipher = $this->makeRotatingCipher();
        $data = '550e8400-e29b-41d4-a716-446655440000';
        $salt = 'user:123';

        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, 'uuid'));
    }

    public function testEmailValidatorAcceptsEmailAddress(): void
    {
        $cipher = $this->makeRotatingCipher();
        $data = 'mark@example.com';
        $salt = 'user:123';

        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, 'email'));
    }

    public function testOptionalRuleAcceptsEmptyString(): void
    {
        $cipher = $this->makeRotatingCipher();
        $data = '';
        $salt = 'user:123';

        $encrypted = $cipher->encrypt($data, $salt);

        $this->assertSame($data, $cipher->decrypt($encrypted, $salt, '?email'));
    }

    public function testCallableValidatorCanForceLegacyFallback(): void
    {
        $cipher = $this->container->make(RotatingCipher::class, [
            'newCipher' => $this->createThrowingCipher(ValidationFailedException::of('new validation failed')),
            'legacyCipher' => $this->createStubCipher('legacy-value', 'legacy-payload', str_repeat('cd', 16)),
        ]);

        $this->assertSame('legacy-value', $cipher->decrypt('payload', 'user:123', static fn (string $value): bool => $value === 'expected'));
    }

    public function testValidatorInterfaceCanForceLegacyFallback(): void
    {
        $cipher = $this->container->make(RotatingCipher::class, [
            'newCipher' => $this->createThrowingCipher(ValidationFailedException::of('new validation failed')),
            'legacyCipher' => $this->createStubCipher('legacy-value', 'legacy-payload', str_repeat('cd', 16)),
            'validator' => new class () implements ValidatorInterface {
                public function validate(string $value, mixed $rule): bool
                {
                    return $value === $rule;
                }
            },
        ]);

        $this->assertSame('legacy-value', $cipher->decrypt('payload', 'user:123', 'expected'));
    }

    public function testInvalidValidatorRaisesException(): void
    {
        $cipher = $this->makeRotatingCipher();

        $this->expectException(Exception::class);
        $cipher->decrypt($cipher->encrypt('test data', 'user:123'), 'user:123', ['not-callable']);
    }

    public function testDecryptWithoutRuleThrowsMissingDecryptRuleException(): void
    {
        $cipher = $this->makeRotatingCipher();
        $payload = $cipher->encrypt('test data', 'user:123');

        $this->expectException(MissingDecryptRuleException::class);
        $cipher->decrypt($payload, 'user:123');
    }

    public function testDecryptWithExplicitNullRuleThrowsMissingDecryptRuleException(): void
    {
        $cipher = $this->makeRotatingCipher();
        $payload = $cipher->encrypt('test data', 'user:123');

        $this->expectException(MissingDecryptRuleException::class);
        $cipher->decrypt($payload, 'user:123', null);
    }

    public function testDecryptWithoutRuleDoesNotInvokeNewCipher(): void
    {
        $newCipher = $this->createMock(CipherInterface::class);
        $newCipher->expects($this->never())->method('decrypt');

        $legacyCipher = $this->createStub(CipherInterface::class);

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->expectException(MissingDecryptRuleException::class);
        $rotating->decrypt('any-payload', 'user:123');
    }

    public function testDecryptWithoutRuleDoesNotInvokeLegacyCipher(): void
    {
        $newCipher = $this->createMock(CipherInterface::class);
        $newCipher->expects($this->never())->method('decrypt');

        $legacyCipher = $this->createMock(CipherInterface::class);
        $legacyCipher->expects($this->never())->method('decrypt');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->expectException(MissingDecryptRuleException::class);
        $rotating->decrypt('any-payload', 'user:123');
    }

    public function testEncryptDelegatesOnlyToNewCipher(): void
    {
        $newCipher = $this->createMock(CipherInterface::class);
        $legacyCipher = $this->createMock(CipherInterface::class);

        $newCipher->expects($this->once())
            ->method('encrypt')
            ->with('plaintext', 'tenant:a')
            ->willReturn('ciphertext-blob');

        $legacyCipher->expects($this->never())->method('encrypt');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->assertSame('ciphertext-blob', $rotating->encrypt('plaintext', 'tenant:a'));
    }

    public function testDecryptSuccessOnNewCipherNeverCallsLegacy(): void
    {
        $newCipher = $this->createMock(CipherInterface::class);
        $legacyCipher = $this->createMock(CipherInterface::class);

        $newCipher->expects($this->once())
            ->method('decrypt')
            ->with('blob', 'user:7', 'uuid')
            ->willReturn('decrypted-value');

        $legacyCipher->expects($this->never())->method('decrypt');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->assertSame('decrypted-value', $rotating->decrypt('blob', 'user:7', 'uuid'));
    }

    public function testLegacyDecryptReceivesPayloadAndKeyWithoutRule(): void
    {
        $newCipher = $this->createStub(CipherInterface::class);
        $newCipher->method('decrypt')->willThrowException(
            DecryptionFailedException::of('new cipher cannot decrypt')
        );

        $legacyCipher = $this->createMock(CipherInterface::class);
        $legacyCipher->expects($this->once())
            ->method('decrypt')
            ->with(
                $this->identicalTo("\x00legacy-payload"),
                $this->identicalTo('logical:key')
            )
            ->willReturn('from-legacy');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->assertSame(
            'from-legacy',
            $rotating->decrypt("\x00legacy-payload", 'logical:key', 'json')
        );
    }

    public function testDecryptPropagatesExceptionWhenLegacyDecryptFails(): void
    {
        $newCipher = $this->createStub(CipherInterface::class);
        $newCipher->method('decrypt')->willThrowException(
            DecryptionFailedException::of('first path failed')
        );

        $legacyCipher = $this->createStub(CipherInterface::class);
        $legacyCipher->method('decrypt')->willThrowException(
            DataTooShortException::of('legacy: payload too short')
        );

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->expectException(DataTooShortException::class);
        $this->expectExceptionMessage('legacy: payload too short');

        $rotating->decrypt('x', 'user:1', 'utf8');
    }

    public function testLegacyFallbackDecryptIsCalledWithoutValidationRuleArgument(): void
    {
        $newCipher = $this->createStub(CipherInterface::class);
        $newCipher->method('decrypt')->willThrowException(
            DecryptionFailedException::of('force legacy fallback')
        );

        $legacyCipher = $this->createMock(CipherInterface::class);
        $legacyCipher->expects($this->once())
            ->method('decrypt')
            ->with('legacy-ciphertext', 'tenant:key')
            ->willReturn('legacy-plaintext');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->assertSame(
            'legacy-plaintext',
            $rotating->decrypt('legacy-ciphertext', 'tenant:key', static fn (string $value): bool => $value !== '')
        );
    }

    public function testDecryptDoesNotCatchNonCryptoExceptionsFromNewCipher(): void
    {
        $newCipher = $this->createStub(CipherInterface::class);
        $newCipher->method('decrypt')->willThrowException(new RuntimeException('internal bug'));

        $legacyCipher = $this->createMock(CipherInterface::class);
        $legacyCipher->expects($this->never())->method('decrypt');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('internal bug');

        $rotating->decrypt('payload', 'user:1', 'email');
    }

    public function testDecryptPropagatesNonCryptoExceptionFromLegacyPath(): void
    {
        $newCipher = $this->createStub(CipherInterface::class);
        $newCipher->method('decrypt')->willThrowException(
            DecryptionFailedException::of('new path')
        );

        $legacyCipher = $this->createStub(CipherInterface::class);
        $legacyCipher->method('decrypt')->willThrowException(new RuntimeException('legacy adapter bug'));

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('legacy adapter bug');

        $rotating->decrypt('payload', 'user:1', 'utf8');
    }

    public function testGetDerivedKeyCallsOnlyNewCipher(): void
    {
        $newCipher = $this->createMock(CipherInterface::class);
        $legacyCipher = $this->createMock(CipherInterface::class);

        $newCipher->expects($this->once())
            ->method('getDerivedKey')
            ->with('jwt:svc', 256)
            ->willReturn('0f' . str_repeat('ab', 31));

        $legacyCipher->expects($this->never())->method('getDerivedKey');

        $rotating = $this->container->make(RotatingCipher::class, [
            'newCipher' => $newCipher,
            'legacyCipher' => $legacyCipher,
        ]);

        $this->assertSame('0f' . str_repeat('ab', 31), $rotating->getDerivedKey('jwt:svc', 256));
    }

    public function testGetDerivedKeyDelegatesToNewCipher(): void
    {
        $newCipher = $this->container->get(CipherInterface::class . '#newCipher');

        $this->assertSame(
            $newCipher->getDerivedKey('tenant:acme', 256),
            $this->rotatingCipher->getDerivedKey('tenant:acme', 256),
        );
    }

    protected function makeRotatingCipher(): RotatingCipher
    {
        return $this->container->make(RotatingCipher::class, [
            'newCipher' => $this->container->get(CipherInterface::class . '#newCipher'),
            'legacyCipher' => $this->container->get(CipherInterface::class . '#legacyCipher'),
            'validator' => new Validator(),
        ]);
    }

    protected function createStubCipher(string $decrypt, string $encrypt, string $derivedKey): CipherInterface
    {
        $cipher = $this->createStub(CipherInterface::class);
        $cipher->method('decrypt')->willReturn($decrypt);
        $cipher->method('encrypt')->willReturn($encrypt);
        $cipher->method('getDerivedKey')->willReturn($derivedKey);

        return $cipher;
    }

    protected function createThrowingCipher(Exception $exception): CipherInterface
    {
        $cipher = $this->createStub(CipherInterface::class);
        $cipher->method('decrypt')->willThrowException($exception);
        $cipher->method('encrypt')->willReturn('new-payload');
        $cipher->method('getDerivedKey')->willReturn(str_repeat('ab', 16));

        return $cipher;
    }
}
