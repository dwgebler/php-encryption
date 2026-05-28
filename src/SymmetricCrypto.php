<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\DecryptionFailedException;
use Gebler\Encryption\Exception\InvalidKeyException;
use Gebler\Encryption\Exception\SodiumOperationException;
use InvalidArgumentException;
use Random\RandomException;
use SodiumException;

/**
 * Authenticated symmetric encryption using XSalsa20-Poly1305 (secretbox).
 *
 * Two modes:
 *  - encryptWithPassword/decryptWithPassword: key derived from password
 *    via Argon2id with a random salt embedded in the ciphertext.
 *  - encryptWithKey/decryptWithKey: caller supplies a 32-byte raw key.
 *
 * Ciphertexts are returned base64-encoded. Internally:
 *  - Password mode layout: salt(16) || nonce(24) || boxed_ciphertext
 *  - Key mode layout:               nonce(24) || boxed_ciphertext
 */
final readonly class SymmetricCrypto
{
    /** @return string 32 random raw bytes. */
    public function generateKey(): string
    {
        return sodium_crypto_secretbox_keygen();
    }

    public function encryptWithKey(string $plaintext, string $key): string
    {
        if ($plaintext === '') {
            throw new InvalidArgumentException('Plaintext must not be empty.');
        }
        $this->assertKeyLength($key);

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        } catch (RandomException $e) {
            throw new SodiumOperationException('Could not generate nonce.', 0, $e);
        }
        $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
        return Encoding::toBase64($nonce . $cipher);
    }

    public function decryptWithKey(string $ciphertext, string $key): string
    {
        $this->assertKeyLength($key);

        $decoded = Encoding::fromBase64($ciphertext);
        $nonceLen = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
        $minLen = $nonceLen + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

        if (strlen($decoded) < $minLen) {
            throw new DecryptionFailedException('Ciphertext is too short to be valid.');
        }

        $nonce = substr($decoded, 0, $nonceLen);
        $cipher = substr($decoded, $nonceLen);

        try {
            $plaintext = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        } catch (SodiumException $e) {
            throw new SodiumOperationException('Symmetric decryption failed.', 0, $e);
        }

        if ($plaintext === false) {
            throw new DecryptionFailedException('Decryption failed: wrong key or tampered ciphertext.');
        }

        return $plaintext;
    }

    public function encryptWithPassword(string $plaintext, string $password): string
    {
        if ($plaintext === '') {
            throw new InvalidArgumentException('Plaintext must not be empty.');
        }

        $key = null;
        try {
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $key = sodium_crypto_pwhash(
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                $password,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            );
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
            return Encoding::toBase64($salt . $nonce . $cipher);
        } catch (SodiumException $e) {
            throw new SodiumOperationException('Password-based encryption failed.', 0, $e);
        } catch (RandomException $e) {
            throw new SodiumOperationException('Could not generate salt or nonce.', 0, $e);
        } finally {
            if ($key !== null) {
                sodium_memzero($key);
            }
        }
    }

    public function decryptWithPassword(string $ciphertext, string $password): string
    {
        $decoded = Encoding::fromBase64($ciphertext);
        $saltLen = SODIUM_CRYPTO_PWHASH_SALTBYTES;
        $nonceLen = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
        $minLen = $saltLen + $nonceLen + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

        if (strlen($decoded) < $minLen) {
            throw new DecryptionFailedException('Ciphertext is too short to be valid.');
        }

        $salt = substr($decoded, 0, $saltLen);
        $nonce = substr($decoded, $saltLen, $nonceLen);
        $cipher = substr($decoded, $saltLen + $nonceLen);

        $key = null;
        try {
            $key = sodium_crypto_pwhash(
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                $password,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            );
            $plaintext = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        } catch (SodiumException $e) {
            throw new SodiumOperationException('Password-based decryption failed.', 0, $e);
        } finally {
            if ($key !== null) {
                sodium_memzero($key);
            }
        }

        if ($plaintext === false) {
            throw new DecryptionFailedException('Decryption failed: wrong password or tampered ciphertext.');
        }

        return $plaintext;
    }

    private function assertKeyLength(string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'Symmetric key must be exactly %d bytes; got %d.',
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                strlen($key),
            ));
        }
    }
}
