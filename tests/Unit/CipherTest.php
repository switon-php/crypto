<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests\Unit;

use Switon\Crypto\Cipher;
use Switon\Crypto\CipherInterface;
use Switon\Crypto\Exception as CipherException;
use Switon\Crypto\Exception\DataTooShortException;
use Switon\Crypto\Exception\DecryptionFailedException;
use Switon\Crypto\Exception\InvalidDerivedKeyBitsException;
use Switon\Crypto\Exception\InvalidRawKeyException;
use Switon\Crypto\Exception\ValidationFailedException;
use Switon\Crypto\Tests\TestCase;
use Switon\Crypto\ValidatorInterface;
use ValueError;

/**
 * Test cases for Cipher class.
 */
class CipherTest extends TestCase
{
    protected Cipher $cipher;
    protected string $secret;
    protected string $encryption_key;

    protected function setUp(): void
    {
        parent::setUp();

        $this->secret = 'test-master-key-123456';
        $this->encryption_key = 'test-encryption-key';

        // Get Cipher instance from container with parameters for dependency injection
        $this->cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
        ]);
    }

    /**
     * Test that encrypt() returns a non-empty string.
     */
    public function testEncryptReturnsNonEmptyString(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);

        // Assert
        $this->assertIsString($encrypted, 'encrypt() should return a string');
        $this->assertNotEmpty($encrypted, 'encrypt() should return non-empty string');
        $this->assertNotSame($plaintext, $encrypted, 'encrypted text should differ from plaintext');
    }

    /**
     * Test that decrypt() returns the original plaintext.
     */
    public function testDecryptReturnsOriginalPlaintext(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'decrypt() should return original plaintext');
    }

    /**
     * Test that decrypt() with wrong key throws exception.
     */
    public function testDecryptWithWrongKeyThrowsException(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';
        $wrongKey = 'wrong-key';
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);

        // Assert & Act
        $this->expectException(CipherException::class);
        $this->cipher->decrypt($encrypted, $wrongKey, static fn (string $value): bool => $value === $plaintext);
    }

    /**
     * Test encryption and decryption with empty string.
     */
    public function testEncryptDecryptWithEmptyString(): void
    {
        // Arrange
        $plaintext = '';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle empty string');
    }

    /**
     * Test encryption and decryption with long text.
     */
    public function testEncryptDecryptWithLongText(): void
    {
        // Arrange
        $plaintext = str_repeat('A', 10000);

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle long text');
    }

    /**
     * Test encryption and decryption with special characters.
     */
    public function testEncryptDecryptWithSpecialCharacters(): void
    {
        // Arrange
        $plaintext = '特殊字符 @#$%^&*()_+-=[]{}|;:,.<>?/~`\'"';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle special characters');
    }

    /**
     * Test encryption and decryption with binary data.
     */
    public function testEncryptDecryptWithBinaryData(): void
    {
        // Arrange
        $plaintext = "\x00\x01\x02\x03\x04\x05\xFF\xFE\xFD\xFC";

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle binary data');
    }

    /**
     * Test that encryption results are different each time (due to random IV).
     */
    public function testEncryptionResultsDifferEachTime(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';

        // Act
        $encrypted1 = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $encrypted2 = $this->cipher->encrypt($plaintext, $this->encryption_key);

        // Assert
        $this->assertNotSame($encrypted1, $encrypted2, 'encryption with random IV should produce different results');
    }

    /**
     * Test that decryption of corrupted data throws exception.
     */
    public function testDecryptCorruptedDataThrowsException(): void
    {
        // Arrange
        // Create long enough corrupted data (>= 32 bytes) to pass length check
        $corruptedData = str_repeat('x', 64);

        // Assert & Act
        $this->expectException(DecryptionFailedException::class);
        $this->cipher->decrypt($corruptedData, $this->encryption_key);
    }

    /**
     * Test that decryption of too short data throws exception.
     */
    public function testDecryptTooShortDataThrowsException(): void
    {
        // Arrange
        $shortData = 'short';

        // Assert & Act
        $this->expectException(DataTooShortException::class);
        $this->cipher->decrypt($shortData, $this->encryption_key);
    }

    /**
     * Test encryption with hex key (lowercase).
     */
    public function testEncryptDecryptWithHexKey(): void
    {
        // Arrange
        $hexKey = '0123456789abcdef0123456789abcdef';  // 32-char hex = 16 bytes
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $hexKey);
        $decrypted = $this->cipher->decrypt($encrypted, $hexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle hex key');
    }

    /**
     * Test that different salts produce different encrypted data.
     */
    public function testDifferentSaltsProduceDifferentEncryption(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';

        // Act
        $encrypted1 = $this->cipher->encrypt($plaintext, 'salt1');
        $encrypted2 = $this->cipher->encrypt($plaintext, 'salt2');

        // Assert
        $this->assertNotSame($encrypted1, $encrypted2, 'different salts should produce different encryption');
    }

    /**
     * Test encryption with empty secret throws exception for non-hex keys.
     */
    public function testEncryptWithEmptySecretThrowsException(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => '',
        ]);
        $plaintext = 'Hello, World!';
        $key = 'my-key';  // Non-hex key

        // Assert & Act
        $this->expectException(ValueError::class);
        $cipher->encrypt($plaintext, $key);
    }

    /**
     * Test encryption with empty secret works for hex keys.
     */
    public function testEncryptWithEmptySecretWorksForHexKeys(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => '',
        ]);
        $plaintext = 'Hello, World!';
        $hexKey = '0123456789abcdef0123456789abcdef';  // 32-char hex

        // Act
        $encrypted = $cipher->encrypt($plaintext, $hexKey);
        $decrypted = $cipher->decrypt($encrypted, $hexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'hex keys should work without secret');
    }

    /**
     * Test encryption and decryption with UTF-8 text.
     */
    public function testEncryptDecryptWithUtf8Text(): void
    {
        // Arrange
        $plaintext = '中文测试 🎉 Test with emoji';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle UTF-8 and emoji');
    }

    public function testDecryptWithValidationRuleAcceptsMatchingData(): void
    {
        $plaintext = '{"name":"John"}';
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);

        $this->assertSame($plaintext, $this->cipher->decrypt($encrypted, $this->encryption_key, 'json'));
    }

    public function testDecryptWithValidationRuleRejectsMismatchedData(): void
    {
        $plaintext = 'not-json';
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);

        $this->expectException(ValidationFailedException::class);
        $this->cipher->decrypt($encrypted, $this->encryption_key, 'json');
    }

    public function testDecryptWithOptionalValidationRuleAcceptsEmptyString(): void
    {
        $encrypted = $this->cipher->encrypt('', $this->encryption_key);

        $this->assertSame('', $this->cipher->decrypt($encrypted, $this->encryption_key, '?email'));
    }

    public function testGetDerivedKeyThrowsWhenSecretEmptyInDerivedMode(): void
    {
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => '',
            'mode' => 'derived',
        ]);

        $this->expectException(ValueError::class);

        $cipher->getDerivedKey('jwt:api', 256);
    }

    public function testGetDerivedKeyIsDeterministicForSameType(): void
    {
        $a = $this->cipher->getDerivedKey('session:abc', 256);
        $b = $this->cipher->getDerivedKey('session:abc', 256);

        $this->assertSame($a, $b);
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $a);
    }

    public function testDerivedKeyLengthMatchesRequestedBits(): void
    {
        $cipher128 = $this->container->make(CipherInterface::class, [
            'secret' => 'stable-secret',
            'method' => 'AES-128-CBC',
            'algo' => 'md5',
        ]);
        $cipher256 = $this->container->make(CipherInterface::class, [
            'secret' => 'stable-secret',
            'method' => 'AES-256-CBC',
            'algo' => 'md5',
        ]);

        $this->assertSame(64, strlen($cipher128->getDerivedKey('jwt', 256)));
        $this->assertSame(128, strlen($cipher256->getDerivedKey('jwt', 512)));
    }

    public function testGetDerivedKeyThrowsWhenBitsAreInvalid(): void
    {
        $this->expectException(InvalidDerivedKeyBitsException::class);
        $this->expectExceptionMessage('must be a positive multiple of 8');

        $this->cipher->getDerivedKey('jwt', 130);
    }

    public function testDecryptWithCallableRuleAccepts(): void
    {
        $plain = 'ORD-20260404';
        $encrypted = $this->cipher->encrypt($plain, $this->encryption_key);

        $decrypted = $this->cipher->decrypt(
            $encrypted,
            $this->encryption_key,
            static fn (string $v): bool => str_starts_with($v, 'ORD-')
        );

        $this->assertSame($plain, $decrypted);
    }

    public function testDecryptWithCallableRuleRejects(): void
    {
        $encrypted = $this->cipher->encrypt('wrong-prefix', $this->encryption_key);

        $this->expectException(ValidationFailedException::class);
        $this->cipher->decrypt(
            $encrypted,
            $this->encryption_key,
            static fn (string $v): bool => str_starts_with($v, 'ORD-')
        );
    }

    public function testDecryptWithCustomValidatorAccepts(): void
    {
        $validator = new class () implements ValidatorInterface {
            public function validate(string $value, mixed $rule): bool
            {
                return $rule === 'pin' && preg_match('/^\d{4}$/', $value) === 1;
            }
        };

        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'validator' => $validator,
        ]);

        $plain = '4242';
        $encrypted = $cipher->encrypt($plain, $this->encryption_key);

        $this->assertSame($plain, $cipher->decrypt($encrypted, $this->encryption_key, 'pin'));
    }

    public function testDecryptWithCustomValidatorRejectsWhenRuleDoesNotMatch(): void
    {
        $validator = new class () implements ValidatorInterface {
            public function validate(string $value, mixed $rule): bool
            {
                return $rule === 'pin' && preg_match('/^\d{4}$/', $value) === 1;
            }
        };

        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'validator' => $validator,
        ]);

        $encrypted = $cipher->encrypt('4242', $this->encryption_key);

        $this->expectException(ValidationFailedException::class);
        $cipher->decrypt($encrypted, $this->encryption_key, 'other-rule');
    }

    /**
     * Test encryption with different encryption method.
     */
    public function testEncryptDecryptWithDifferentMethod(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'method' => 'AES-256-CBC',
        ]);
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'AES-256-CBC should work correctly');
    }

    /**
     * Test that encrypted data includes IV (first bytes).
     */
    public function testEncryptedDataIncludesIV(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);

        // Assert
        $this->assertGreaterThanOrEqual(16, strlen($encrypted), 'encrypted data should include IV');
        $this->assertNotSame($plaintext, $encrypted, 'encrypted data should differ from plaintext');

        $decrypted = $this->cipher->decrypt($encrypted, $this->encryption_key);
        $this->assertSame($plaintext, $decrypted, 'decryption should work with IV included');
    }

    /**
     * Test that decryption with truncated data throws exception.
     */
    public function testDecryptWithTruncatedDataThrowsException(): void
    {
        // Arrange
        $plaintext = 'Hello, World!';
        $encrypted = $this->cipher->encrypt($plaintext, $this->encryption_key);
        $corrupted = substr($encrypted, 0, strlen($encrypted) - 10);

        // Assert & Act
        $this->expectException(CipherException::class);
        $this->cipher->decrypt($corrupted, $this->encryption_key);
    }

    /**
     * Test encryption with empty key.
     */
    public function testEncryptDecryptWithEmptyKey(): void
    {
        // Arrange
        $emptyKey = '';
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $emptyKey);
        $decrypted = $this->cipher->decrypt($encrypted, $emptyKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle empty key');
    }

    /**
     * Test encryption with very long key.
     */
    public function testEncryptDecryptWithLongKey(): void
    {
        // Arrange
        $longKey = str_repeat('A', 1000);
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $longKey);
        $decrypted = $this->cipher->decrypt($encrypted, $longKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle long key');
    }

    /**
     * Test encryption with different hash algorithm (SHA256).
     */
    public function testEncryptDecryptWithDifferentAlgo(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'algo' => 'sha256',
        ]);
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'SHA256 should work correctly');
    }

    /**
     * Test hex key with mixed case is not treated as hex key.
     */
    public function testMixedCaseHexKeyTreatedAsSalt(): void
    {
        // Arrange
        $mixedCaseKey = '0123456789ABCDEF0123456789abcdef';  // Mixed case
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $mixedCaseKey);
        $decrypted = $this->cipher->decrypt($encrypted, $mixedCaseKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'mixed case hex should be treated as salt');
    }

    /**
     * Test hex key must be exactly 32 or 64 characters.
     */
    public function testShortHexKeyTreatedAsSalt(): void
    {
        // Arrange
        $shortHexKey = '0123456789abcdef0123456789abcde';  // 31 chars
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $shortHexKey);
        $decrypted = $this->cipher->decrypt($encrypted, $shortHexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'short hex key should be treated as salt');
    }

    /**
     * Test 33-char hex key is treated as salt (not raw key).
     */
    public function testOddLengthHexKeyTreatedAsSalt(): void
    {
        // Arrange
        $oddHexKey = '0123456789abcdef0123456789abcdef0';  // 33 chars
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $oddHexKey);
        $decrypted = $this->cipher->decrypt($encrypted, $oddHexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, '33-char hex key should be treated as salt');
    }

    // =========================================================================
    // AEAD (GCM) tests
    // =========================================================================

    /**
     * Test AES-256-GCM encrypt/decrypt round trip.
     */
    public function testEncryptDecryptWithGcm(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'method' => 'AES-256-GCM',
        ]);
        $plaintext = 'Hello, GCM World!';

        // Act
        $encrypted = $cipher->encrypt($plaintext, $this->encryption_key);
        $decrypted = $cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'GCM round trip should work');
    }

    /**
     * Test GCM output includes IV (12 bytes) + ciphertext + tag (16 bytes).
     */
    public function testGcmOutputIncludesTag(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'method' => 'AES-256-GCM',
        ]);
        $plaintext = 'test'; // 4 bytes

        // Act
        $encrypted = $cipher->encrypt($plaintext, $this->encryption_key);

        // Assert — GCM: IV (12) + ciphertext (same as plaintext, no padding) + tag (16)
        $expectedLength = 12 + strlen($plaintext) + 16;
        $this->assertSame(
            $expectedLength,
            strlen($encrypted),
            'GCM output should be IV + ciphertext (no padding) + 16-byte tag'
        );
    }

    /**
     * Test GCM detects tampered ciphertext (authentication).
     */
    public function testGcmDetectsTamperedData(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'method' => 'AES-256-GCM',
        ]);
        $encrypted = $cipher->encrypt('secret data', $this->encryption_key);

        // Tamper with ciphertext (flip a byte after IV, before tag)
        $tampered = $encrypted;
        $tampered[16] = chr(ord($tampered[16]) ^ 0xFF);

        // Assert & Act
        $this->expectException(DecryptionFailedException::class);
        $cipher->decrypt($tampered, $this->encryption_key);
    }

    /**
     * Test GCM with wrong key throws exception.
     */
    public function testGcmWithWrongKeyThrowsException(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'method' => 'AES-256-GCM',
        ]);
        $encrypted = $cipher->encrypt('data', $this->encryption_key);

        // Assert & Act
        $this->expectException(DecryptionFailedException::class);
        $cipher->decrypt($encrypted, 'wrong-key');
    }

    /**
     * Test GCM with empty string.
     */
    public function testGcmWithEmptyString(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'method' => 'AES-256-GCM',
        ]);

        // Act
        $encrypted = $cipher->encrypt('', $this->encryption_key);
        $decrypted = $cipher->decrypt($encrypted, $this->encryption_key);

        // Assert
        $this->assertSame('', $decrypted, 'GCM should handle empty string');
    }

    // =========================================================================
    // Mode tests
    // =========================================================================

    /**
     * Test mode=derived always derives, even with hex-like salt.
     */
    public function testModeDerivedIgnoresHexDetection(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'derived',
        ]);
        $hexLikeSalt = '550e8400e29b41d4a716446655440000'; // UUID without hyphens (32 hex chars)
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $cipher->encrypt($plaintext, $hexLikeSalt);
        $decrypted = $cipher->decrypt($encrypted, $hexLikeSalt);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'mode=derived should treat hex-like string as salt');
    }

    /**
     * Test mode=derived produces different result than mode=auto for same hex key.
     */
    public function testModeDerivedDiffersFromAutoForHexKey(): void
    {
        // Arrange
        $hexKey = '0123456789abcdef0123456789abcdef';
        $plaintext = 'Hello, World!';

        $autoCipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'auto',
        ]);
        $derivedCipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'derived',
        ]);

        // Act
        $autoEncrypted = $autoCipher->encrypt($plaintext, $hexKey);
        $derivedEncrypted = $derivedCipher->encrypt($plaintext, $hexKey);

        // Assert — auto uses hex2bin, derived uses HKDF, so cross-decryption should fail
        $this->expectException(CipherException::class);
        $derivedCipher->decrypt($autoEncrypted, $hexKey);
    }

    /**
     * Test mode=raw works with valid hex key.
     */
    public function testModeRawWithValidHexKey(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'raw',
        ]);
        $hexKey = '0123456789abcdef0123456789abcdef';
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $cipher->encrypt($plaintext, $hexKey);
        $decrypted = $cipher->decrypt($encrypted, $hexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'mode=raw should work with valid hex key');
    }

    /**
     * Test mode=raw throws on non-hex key.
     */
    public function testModeRawThrowsOnNonHexKey(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'raw',
        ]);

        // Assert & Act
        $this->expectException(InvalidRawKeyException::class);
        $cipher->encrypt('data', 'user:123');
    }

    /**
     * Test mode=raw throws on short hex key.
     */
    public function testModeRawThrowsOnShortHexKey(): void
    {
        // Arrange
        $cipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'raw',
        ]);

        // Assert & Act
        $this->expectException(InvalidRawKeyException::class);
        $cipher->encrypt('data', '0123456789abcdef'); // 16 chars, < 32
    }

    /**
     * Test mode=auto preserves backward-compatible hex detection.
     */
    public function testModeAutoDetectsHexKey(): void
    {
        // Arrange
        $autoCipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'auto',
        ]);
        $rawCipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'raw',
        ]);
        $hexKey = '0123456789abcdef0123456789abcdef';
        $plaintext = 'Hello, World!';

        // Act — both should use the same raw key derivation
        $encrypted = $autoCipher->encrypt($plaintext, $hexKey);
        $decrypted = $rawCipher->decrypt($encrypted, $hexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'mode=auto hex detection should produce same key as mode=raw');
    }

    /**
     * Test mode=auto treats non-hex as salt.
     */
    public function testModeAutoTreatsNonHexAsSalt(): void
    {
        // Arrange
        $autoCipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'auto',
        ]);
        $derivedCipher = $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'derived',
        ]);
        $salt = 'user:123';
        $plaintext = 'Hello, World!';

        // Act — both should derive via HKDF
        $encrypted = $autoCipher->encrypt($plaintext, $salt);
        $decrypted = $derivedCipher->decrypt($encrypted, $salt);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'mode=auto with non-hex should produce same key as mode=derived');
    }

    /**
     * Test invalid mode throws exception.
     */
    public function testInvalidModeThrowsException(): void
    {
        $this->expectException(ValueError::class);

        $this->container->make(CipherInterface::class, [
            'secret' => $this->secret,
            'mode' => 'invalid',
        ]);
    }

    /**
     * Test data encrypted with one secret cannot be decrypted with another.
     */
    public function testDifferentSecretCannotDecrypt(): void
    {
        // Arrange
        $cipher1 = $this->container->make(CipherInterface::class, [
            'secret' => 'secret1',
        ]);
        $cipher2 = $this->container->make(CipherInterface::class, [
            'secret' => 'secret2',
        ]);
        $plaintext = 'Hello, World!';
        $encrypted = $cipher1->encrypt($plaintext, $this->encryption_key);

        // Assert & Act
        $this->expectException(CipherException::class);
        $cipher2->decrypt($encrypted, $this->encryption_key);
    }

    /**
     * Test hex key with 64 characters (32 bytes) for AES-256.
     */
    public function testEncryptDecryptWithLongHexKey(): void
    {
        // Arrange
        $hexKey = str_repeat('0123456789abcdef', 4);  // 64-char hex = 32 bytes
        $plaintext = 'Hello, World!';

        // Act
        $encrypted = $this->cipher->encrypt($plaintext, $hexKey);
        $decrypted = $this->cipher->decrypt($encrypted, $hexKey);

        // Assert
        $this->assertSame($plaintext, $decrypted, 'should handle 64-char hex key');
    }
}
