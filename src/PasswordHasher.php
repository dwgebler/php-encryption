<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\SodiumOperationException;
use SodiumException;

/**
 * Argon2id password hashing for storage and verification.
 *
 * Use this for storing user passwords. Do NOT use it as a key derivation
 * function for symmetric encryption — see SymmetricCrypto::encryptWithPassword
 * for that.
 */
final readonly class PasswordHasher
{
    public const OPSLIMIT_INTERACTIVE = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    public const OPSLIMIT_MODERATE    = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
    public const OPSLIMIT_SENSITIVE   = SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE;
    public const MEMLIMIT_INTERACTIVE = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    public const MEMLIMIT_MODERATE    = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
    public const MEMLIMIT_SENSITIVE   = SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE;

    public function __construct(
        private int $opsLimit = self::OPSLIMIT_MODERATE,
        private int $memLimit = self::MEMLIMIT_MODERATE,
    ) {
    }

    /**
     * Hash a password for storage. Returns an Argon2id verifier string
     * (starts with $argon2id$) that includes the salt and parameters.
     */
    public function hash(string $password): string
    {
        try {
            return sodium_crypto_pwhash_str($password, $this->opsLimit, $this->memLimit);
        } catch (SodiumException $e) {
            throw new SodiumOperationException('Password hashing failed.', 0, $e);
        }
    }

    /**
     * Verify a password against a previously-generated hash. Returns false
     * for both wrong passwords and malformed hashes — never throws on a
     * verification mismatch.
     */
    public function verify(string $password, string $hash): bool
    {
        try {
            return sodium_crypto_pwhash_str_verify($hash, $password);
        } catch (SodiumException) {
            return false;
        }
    }

    /**
     * True if the stored hash was not generated with this hasher's
     * current ops/mem parameters. Re-hash on next login to bring the
     * record in line with current settings. Returns true for any
     * parameter mismatch, including downgrades — not only upgrades.
     */
    public function needsRehash(string $hash): bool
    {
        return sodium_crypto_pwhash_str_needs_rehash($hash, $this->opsLimit, $this->memLimit);
    }
}
