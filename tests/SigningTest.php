<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\Encoding;
use Gebler\Encryption\Exception\DecryptionFailedException;
use Gebler\Encryption\Exception\InvalidKeyException;
use Gebler\Encryption\Signing;
use Gebler\Encryption\SigningKeyPair;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SigningTest extends TestCase
{
    private Signing $signing;

    #[\Override]
    protected function setUp(): void
    {
        $this->signing = new Signing();
    }

    public function testGenerateKeypairReturnsValidLengths(): void
    {
        $kp = $this->signing->generateKeypair();
        self::assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($kp->publicKey));
        self::assertSame(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, strlen($kp->privateKey));
    }

    public function testSignAttachedAndOpenRoundTrip(): void
    {
        $kp = $this->signing->generateKeypair();
        $signed = $this->signing->signAttached('hello', $kp->privateKey);
        self::assertSame('hello', $this->signing->openAttached($signed, $kp->publicKey));
    }

    public function testOpenAttachedFailsForWrongPublicKey(): void
    {
        $kp = $this->signing->generateKeypair();
        $other = $this->signing->generateKeypair();
        $signed = $this->signing->signAttached('hello', $kp->privateKey);
        $this->expectException(DecryptionFailedException::class);
        $this->signing->openAttached($signed, $other->publicKey);
    }

    public function testOpenAttachedFailsForTamperedSignedMessage(): void
    {
        $kp = $this->signing->generateKeypair();
        $signed = $this->signing->signAttached('hello world', $kp->privateKey);
        $raw = Encoding::fromBase64($signed);
        $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 0x01);
        $this->expectException(DecryptionFailedException::class);
        $this->signing->openAttached(Encoding::toBase64($raw), $kp->publicKey);
    }

    public function testSignDetachedAndVerifyRoundTrip(): void
    {
        $kp = $this->signing->generateKeypair();
        $signature = $this->signing->signDetached('hello', $kp->privateKey);
        self::assertSame(SODIUM_CRYPTO_SIGN_BYTES, strlen(Encoding::fromHex($signature)));
        self::assertTrue($this->signing->verifyDetached($signature, 'hello', $kp->publicKey));
    }

    public function testVerifyDetachedFailsForWrongMessage(): void
    {
        $kp = $this->signing->generateKeypair();
        $signature = $this->signing->signDetached('hello', $kp->privateKey);
        self::assertFalse($this->signing->verifyDetached($signature, 'goodbye', $kp->publicKey));
    }

    public function testVerifyDetachedFailsForWrongPublicKey(): void
    {
        $kp = $this->signing->generateKeypair();
        $other = $this->signing->generateKeypair();
        $signature = $this->signing->signDetached('hello', $kp->privateKey);
        self::assertFalse($this->signing->verifyDetached($signature, 'hello', $other->publicKey));
    }

    public function testSignAttachedRejectsEmptyMessage(): void
    {
        $kp = $this->signing->generateKeypair();
        $this->expectException(InvalidArgumentException::class);
        $this->signing->signAttached('', $kp->privateKey);
    }

    public function testSignDetachedRejectsEmptyMessage(): void
    {
        $kp = $this->signing->generateKeypair();
        $this->expectException(InvalidArgumentException::class);
        $this->signing->signDetached('', $kp->privateKey);
    }

    public function testSignAttachedRejectsWrongKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->signing->signAttached('hello', str_repeat("\0", 16));
    }

    public function testVerifyDetachedReturnsFalseForWrongSignatureLength(): void
    {
        $kp = $this->signing->generateKeypair();
        self::assertFalse($this->signing->verifyDetached(Encoding::toHex(str_repeat("\0", 16)), 'hi', $kp->publicKey));
    }

    public function testVerifyDetachedReturnsFalseForNonHexSignature(): void
    {
        $kp = $this->signing->generateKeypair();
        self::assertFalse($this->signing->verifyDetached('not-hex-data!', 'hi', $kp->publicKey));
    }

    public function testSigningKeyPairConstructorRejectsWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        new SigningKeyPair(str_repeat("\0", 16), str_repeat("\0", 64));
    }
}
