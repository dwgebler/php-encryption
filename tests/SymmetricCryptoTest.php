<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\Encoding;
use Gebler\Encryption\Exception\DecryptionFailedException;
use Gebler\Encryption\Exception\InvalidKeyException;
use Gebler\Encryption\SymmetricCrypto;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SymmetricCryptoTest extends TestCase
{
    private SymmetricCrypto $crypto;

    protected function setUp(): void
    {
        $this->crypto = new SymmetricCrypto();
    }

    public function testGenerateKeyReturns32Bytes(): void
    {
        self::assertSame(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, strlen($this->crypto->generateKey()));
    }

    public function testEncryptWithKeyRoundTrip(): void
    {
        $key = $this->crypto->generateKey();
        $plaintext = 'Hello, world!';
        $ciphertext = $this->crypto->encryptWithKey($plaintext, $key);
        self::assertNotSame($plaintext, $ciphertext);
        self::assertSame($plaintext, $this->crypto->decryptWithKey($ciphertext, $key));
    }

    public function testEncryptWithKeyRoundTripWithBinaryPayload(): void
    {
        $key = $this->crypto->generateKey();
        $plaintext = random_bytes(1024);
        $ciphertext = $this->crypto->encryptWithKey($plaintext, $key);
        self::assertSame($plaintext, $this->crypto->decryptWithKey($ciphertext, $key));
    }

    public function testEncryptWithKeyRoundTripWithMultibyteUtf8(): void
    {
        $key = $this->crypto->generateKey();
        $plaintext = '日本語のテスト 🔐 with emoji';
        $ciphertext = $this->crypto->encryptWithKey($plaintext, $key);
        self::assertSame($plaintext, $this->crypto->decryptWithKey($ciphertext, $key));
    }

    public function testEncryptWithKeyRejectsEmptyPlaintext(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->crypto->encryptWithKey('', $this->crypto->generateKey());
    }

    public function testEncryptWithKeyRejectsShortKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->crypto->encryptWithKey('msg', str_repeat("\0", 16));
    }

    public function testEncryptWithKeyRejectsLongKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->crypto->encryptWithKey('msg', str_repeat("\0", 33));
    }

    public function testDecryptWithKeyFailsForWrongKey(): void
    {
        $key = $this->crypto->generateKey();
        $ciphertext = $this->crypto->encryptWithKey('secret', $key);
        $otherKey = $this->crypto->generateKey();
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptWithKey($ciphertext, $otherKey);
    }

    public function testDecryptWithKeyFailsForTamperedCiphertext(): void
    {
        $key = $this->crypto->generateKey();
        $ciphertext = $this->crypto->encryptWithKey('secret payload', $key);
        $raw = Encoding::fromBase64($ciphertext);
        // Flip the last byte (part of the MAC or final block).
        $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 0x01);
        $tampered = Encoding::toBase64($raw);
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptWithKey($tampered, $key);
    }

    public function testDecryptWithKeyRejectsTooShortCiphertext(): void
    {
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptWithKey(Encoding::toBase64(str_repeat("\0", 4)), $this->crypto->generateKey());
    }

    public function testEncryptWithPasswordRoundTrip(): void
    {
        $ciphertext = $this->crypto->encryptWithPassword('hello', 'correct horse battery staple');
        self::assertSame('hello', $this->crypto->decryptWithPassword($ciphertext, 'correct horse battery staple'));
    }

    public function testEncryptWithPasswordRoundTripWithBinaryPayload(): void
    {
        $plaintext = random_bytes(1024);
        $ciphertext = $this->crypto->encryptWithPassword($plaintext, 'pw');
        self::assertSame($plaintext, $this->crypto->decryptWithPassword($ciphertext, 'pw'));
    }

    public function testEncryptWithPasswordRejectsEmptyPlaintext(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->crypto->encryptWithPassword('', 'password');
    }

    public function testDecryptWithPasswordFailsForWrongPassword(): void
    {
        $ciphertext = $this->crypto->encryptWithPassword('hello', 'right');
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptWithPassword($ciphertext, 'wrong');
    }

    public function testDecryptWithPasswordFailsForTamperedCiphertext(): void
    {
        $ciphertext = $this->crypto->encryptWithPassword('hello', 'pw');
        $raw = Encoding::fromBase64($ciphertext);
        $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 0x01);
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptWithPassword(Encoding::toBase64($raw), 'pw');
    }
}
