<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    private PasswordHasher $hasher;

    #[\Override]
    protected function setUp(): void
    {
        // Use INTERACTIVE ops/mem in tests so the suite stays fast.
        $this->hasher = new PasswordHasher(
            PasswordHasher::OPSLIMIT_INTERACTIVE,
            PasswordHasher::MEMLIMIT_INTERACTIVE,
        );
    }

    public function testHashProducesArgon2idVerifierString(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');
        // Sodium's Argon2id verifier strings begin with $argon2id$
        self::assertStringStartsWith('$argon2id$', $hash);
    }

    public function testHashIsNotDeterministic(): void
    {
        $a = $this->hasher->hash('same password');
        $b = $this->hasher->hash('same password');
        self::assertNotSame($a, $b, 'Argon2id includes a random salt, so the hash must differ.');
    }

    public function testVerifyReturnsTrueForCorrectPassword(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');
        self::assertTrue($this->hasher->verify('correct horse battery staple', $hash));
    }

    public function testVerifyReturnsFalseForWrongPassword(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');
        self::assertFalse($this->hasher->verify('wrong password', $hash));
    }

    public function testVerifyReturnsFalseForMalformedHash(): void
    {
        self::assertFalse($this->hasher->verify('anything', 'not-a-real-hash'));
    }

    public function testNeedsRehashIsFalseForCurrentParameters(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');
        self::assertFalse($this->hasher->needsRehash($hash));
    }

    public function testNeedsRehashIsTrueWhenHasherUsesStrongerParameters(): void
    {
        $weakHasher = new PasswordHasher(
            PasswordHasher::OPSLIMIT_INTERACTIVE,
            PasswordHasher::MEMLIMIT_INTERACTIVE,
        );
        $strongHasher = new PasswordHasher(
            PasswordHasher::OPSLIMIT_MODERATE,
            PasswordHasher::MEMLIMIT_MODERATE,
        );
        $weakHash = $weakHasher->hash('password');
        self::assertTrue($strongHasher->needsRehash($weakHash));
    }
}
