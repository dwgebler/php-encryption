<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\AsymmetricCrypto;
use Gebler\Encryption\Encryption;
use Gebler\Encryption\Mac;
use Gebler\Encryption\PasswordHasher;
use Gebler\Encryption\Signing;
use Gebler\Encryption\SymmetricCrypto;
use PHPUnit\Framework\TestCase;

final class EncryptionTest extends TestCase
{
    private Encryption $crypt;

    #[\Override]
    protected function setUp(): void
    {
        $this->crypt = new Encryption();
    }

    public function testPasswordsAccessorReturnsPasswordHasher(): void
    {
        self::assertInstanceOf(PasswordHasher::class, $this->crypt->passwords());
    }

    public function testSymmetricAccessorReturnsSymmetricCrypto(): void
    {
        self::assertInstanceOf(SymmetricCrypto::class, $this->crypt->symmetric());
    }

    public function testAsymmetricAccessorReturnsAsymmetricCrypto(): void
    {
        self::assertInstanceOf(AsymmetricCrypto::class, $this->crypt->asymmetric());
    }

    public function testSigningAccessorReturnsSigning(): void
    {
        self::assertInstanceOf(Signing::class, $this->crypt->signing());
    }

    public function testMacAccessorReturnsMac(): void
    {
        self::assertInstanceOf(Mac::class, $this->crypt->mac());
    }

    public function testAccessorsAreCachedAcrossCalls(): void
    {
        self::assertSame($this->crypt->passwords(), $this->crypt->passwords());
        self::assertSame($this->crypt->symmetric(), $this->crypt->symmetric());
        self::assertSame($this->crypt->asymmetric(), $this->crypt->asymmetric());
        self::assertSame($this->crypt->signing(), $this->crypt->signing());
        self::assertSame($this->crypt->mac(), $this->crypt->mac());
    }

    public function testEndToEndSymmetricRoundTripViaFacade(): void
    {
        $sym = $this->crypt->symmetric();
        $key = $sym->generateKey();
        self::assertSame('hi', $sym->decryptWithKey($sym->encryptWithKey('hi', $key), $key));
    }
}
