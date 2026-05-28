<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\EncryptionException;

/**
 * Facade exposing the five primitive crypto classes via lazy accessors.
 * Each accessor returns the same instance on repeated calls within the
 * lifetime of one Encryption object.
 *
 * Construct once per process, or per request in long-running workers.
 */
final class Encryption
{
    private ?PasswordHasher $passwords = null;
    private ?SymmetricCrypto $symmetric = null;
    private ?AsymmetricCrypto $asymmetric = null;
    private ?Signing $signing = null;
    private ?Mac $mac = null;

    public function __construct()
    {
        if (!extension_loaded('sodium')) {
            throw new EncryptionException('The sodium extension is not loaded.');
        }
    }

    public function passwords(): PasswordHasher
    {
        return $this->passwords ??= new PasswordHasher();
    }

    public function symmetric(): SymmetricCrypto
    {
        return $this->symmetric ??= new SymmetricCrypto();
    }

    public function asymmetric(): AsymmetricCrypto
    {
        return $this->asymmetric ??= new AsymmetricCrypto();
    }

    public function signing(): Signing
    {
        return $this->signing ??= new Signing();
    }

    public function mac(): Mac
    {
        return $this->mac ??= new Mac();
    }
}
