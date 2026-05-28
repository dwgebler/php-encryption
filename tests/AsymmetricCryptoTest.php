<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\AsymmetricCrypto;
use Gebler\Encryption\Encoding;
use Gebler\Encryption\Exception\DecryptionFailedException;
use Gebler\Encryption\Exception\InvalidKeyException;
use Gebler\Encryption\KeyPair;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class AsymmetricCryptoTest extends TestCase
{
    private AsymmetricCrypto $crypto;

    protected function setUp(): void
    {
        $this->crypto = new AsymmetricCrypto();
    }

    public function testGenerateKeypairReturnsValidLengths(): void
    {
        $kp = $this->crypto->generateKeypair();
        self::assertSame(SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, strlen($kp->publicKey));
        self::assertSame(SODIUM_CRYPTO_BOX_SECRETKEYBYTES, strlen($kp->privateKey));
    }

    public function testAnonymousRoundTrip(): void
    {
        $recipient = $this->crypto->generateKeypair();
        $plaintext = 'Hello, anonymous world.';
        $ciphertext = $this->crypto->encryptAnonymous($plaintext, $recipient->publicKey);
        self::assertNotSame($plaintext, $ciphertext);
        self::assertSame($plaintext, $this->crypto->decryptAnonymous($ciphertext, $recipient));
    }

    public function testAuthenticatedRoundTrip(): void
    {
        $alice = $this->crypto->generateKeypair();
        $bob = $this->crypto->generateKeypair();
        $plaintext = 'Hello Bob, from Alice.';
        $ciphertext = $this->crypto->encryptAuthenticated($plaintext, $bob->publicKey, $alice->privateKey);
        self::assertSame(
            $plaintext,
            $this->crypto->decryptAuthenticated($ciphertext, $bob->privateKey, $alice->publicKey),
        );
    }

    public function testAuthenticatedDecryptFailsWithWrongSender(): void
    {
        $alice = $this->crypto->generateKeypair();
        $bob = $this->crypto->generateKeypair();
        $eve = $this->crypto->generateKeypair();
        $ciphertext = $this->crypto->encryptAuthenticated('msg', $bob->publicKey, $alice->privateKey);
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptAuthenticated($ciphertext, $bob->privateKey, $eve->publicKey);
    }

    public function testAuthenticatedDecryptFailsWithWrongRecipient(): void
    {
        $alice = $this->crypto->generateKeypair();
        $bob = $this->crypto->generateKeypair();
        $mallory = $this->crypto->generateKeypair();
        $ciphertext = $this->crypto->encryptAuthenticated('msg', $bob->publicKey, $alice->privateKey);
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptAuthenticated($ciphertext, $mallory->privateKey, $alice->publicKey);
    }

    public function testAnonymousDecryptFailsWithWrongRecipient(): void
    {
        $bob = $this->crypto->generateKeypair();
        $mallory = $this->crypto->generateKeypair();
        $ciphertext = $this->crypto->encryptAnonymous('msg', $bob->publicKey);
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptAnonymous($ciphertext, $mallory);
    }

    public function testAnonymousDecryptFailsForTamperedCiphertext(): void
    {
        $recipient = $this->crypto->generateKeypair();
        $ciphertext = $this->crypto->encryptAnonymous('payload', $recipient->publicKey);
        $raw = Encoding::fromBase64($ciphertext);
        $raw[0] = chr(ord($raw[0]) ^ 0x01);
        $this->expectException(DecryptionFailedException::class);
        $this->crypto->decryptAnonymous(Encoding::toBase64($raw), $recipient);
    }

    public function testEncryptAnonymousRejectsEmptyPlaintext(): void
    {
        $recipient = $this->crypto->generateKeypair();
        $this->expectException(InvalidArgumentException::class);
        $this->crypto->encryptAnonymous('', $recipient->publicKey);
    }

    public function testEncryptAuthenticatedRejectsEmptyPlaintext(): void
    {
        $alice = $this->crypto->generateKeypair();
        $bob = $this->crypto->generateKeypair();
        $this->expectException(InvalidArgumentException::class);
        $this->crypto->encryptAuthenticated('', $bob->publicKey, $alice->privateKey);
    }

    public function testEncryptAnonymousRejectsWrongPublicKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->crypto->encryptAnonymous('msg', str_repeat("\0", 16));
    }

    public function testEncryptAuthenticatedRejectsWrongPrivateKeyLength(): void
    {
        $bob = $this->crypto->generateKeypair();
        $this->expectException(InvalidKeyException::class);
        $this->crypto->encryptAuthenticated('msg', $bob->publicKey, str_repeat("\0", 16));
    }

    public function testKeyPairConstructorRejectsWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        new KeyPair(str_repeat("\0", 16), str_repeat("\0", 32));
    }
}
