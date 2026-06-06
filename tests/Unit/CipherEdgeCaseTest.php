<?php

declare(strict_types=1);

namespace Switon\Crypto\Tests\Unit;

use Switon\Crypto\Cipher;
use Switon\Crypto\CipherInterface;
use Switon\Crypto\Exception\DataTooShortException;
use Switon\Crypto\Exception\DecryptionFailedException;
use Switon\Crypto\Exception\InvalidRawKeyException;
use Switon\Crypto\Tests\TestCase;
use ValueError;

class CipherEdgeCaseTest extends TestCase
{
    public function testRawModeRejectsInvalidRawKey(): void
    {
        $cipher = $this->container->make(Cipher::class, [
            'secret' => '',
            'mode' => 'raw',
        ]);

        $this->expectException(InvalidRawKeyException::class);
        $cipher->encrypt('payload', 'not-hex');
    }

    public function testRawModeAcceptsValidHexKeyWithoutSecret(): void
    {
        $cipher = $this->container->make(Cipher::class, [
            'secret' => '',
            'mode' => 'raw',
            'method' => 'AES-128-CBC',
        ]);

        $rawKey = '0123456789abcdef0123456789abcdef';
        $encrypted = $cipher->encrypt('payload', $rawKey);

        $this->assertSame('payload', $cipher->decrypt($encrypted, $rawKey));
    }

    public function testInvalidModeRaisesException(): void
    {
        $this->expectException(ValueError::class);

        $this->container->make(Cipher::class, [
            'secret' => 'secret',
            'mode' => 'unsupported',
        ]);
    }

    public function testInvalidCipherMethodRaisesException(): void
    {
        $this->expectException(ValueError::class);

        $this->container->make(Cipher::class, [
            'secret' => 'secret',
            'method' => 'NOT-A-CIPHER',
        ]);
    }

    public function testAeadMethodRoundTripAndTamperDetection(): void
    {
        $cipher = $this->container->make(CipherInterface::class, [
            'class' => Cipher::class,
            'secret' => 'test-master-key',
            'method' => 'AES-256-GCM',
            'algo' => 'sha256',
        ]);

        $encrypted = $cipher->encrypt('payload-gcm', 'user:42');
        $this->assertSame('payload-gcm', $cipher->decrypt($encrypted, 'user:42'));

        $tampered = substr($encrypted, 0, -1) . chr(ord(substr($encrypted, -1)) ^ 0x01);

        $this->expectException(DecryptionFailedException::class);
        $cipher->decrypt($tampered, 'user:42');
    }

    public function testGcmDecryptDataTooShortBelowIvPlusTag(): void
    {
        $cipher = $this->container->make(CipherInterface::class, [
            'class' => Cipher::class,
            'secret' => 'edge-case-master',
            'method' => 'AES-256-GCM',
            'algo' => 'sha256',
        ]);

        $ivLen = openssl_cipher_iv_length('AES-256-GCM');
        $this->assertSame(12, $ivLen);

        $tooShort = str_repeat("\x00", $ivLen + 16 - 1);

        $this->expectException(DataTooShortException::class);
        $cipher->decrypt($tooShort, 'user:1');
    }

    public function testCbcDecryptDataTooShortBeforeAnyCiphertext(): void
    {
        $cipher = $this->container->make(Cipher::class, [
            'secret' => 'secret-for-cbc-short',
            'method' => 'AES-128-CBC',
        ]);

        $ivLen = openssl_cipher_iv_length('AES-128-CBC');
        $this->assertGreaterThan(0, $ivLen);

        $this->expectException(DataTooShortException::class);
        $cipher->decrypt(str_repeat('z', $ivLen - 1), 'salt');
    }

}
