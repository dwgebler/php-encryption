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
 * X25519 + XSalsa20-Poly1305 box encryption.
 *
 * Two modes:
 *  - Anonymous: encrypt to a recipient public key; the recipient decrypts
 *    using their full keypair. The sender is not authenticated.
 *  - Authenticated: encrypt to a recipient public key with a sender private
 *    key; the recipient decrypts with their private key and the sender's
 *    public key. Both sides authenticated.
 *
 * Anonymous ciphertext is base64 of sodium_crypto_box_seal output.
 * Authenticated ciphertext is base64 of nonce(24) || sodium_crypto_box output.
 */
final readonly class AsymmetricCrypto
{
    public function generateKeypair(): KeyPair
    {
        $raw = sodium_crypto_box_keypair();
        return new KeyPair(
            sodium_crypto_box_publickey($raw),
            sodium_crypto_box_secretkey($raw),
        );
    }

    public function encryptAnonymous(string $plaintext, string $recipientPublicKey): string
    {
        if ($plaintext === '') {
            throw new InvalidArgumentException('Plaintext must not be empty.');
        }
        $this->assertLength($recipientPublicKey, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'recipient public key');

        $cipher = sodium_crypto_box_seal($plaintext, $recipientPublicKey);
        return Encoding::toBase64($cipher);
    }

    public function decryptAnonymous(string $ciphertext, KeyPair $recipient): string
    {
        $decoded = Encoding::fromBase64($ciphertext);

        $combined = $recipient->privateKey . $recipient->publicKey;
        try {
            $plaintext = sodium_crypto_box_seal_open($decoded, $combined);
        } finally {
            sodium_memzero($combined);
        }

        if ($plaintext === false) {
            throw new DecryptionFailedException('Decryption failed: wrong recipient or tampered ciphertext.');
        }

        return $plaintext;
    }

    public function encryptAuthenticated(
        string $plaintext,
        string $recipientPublicKey,
        string $senderPrivateKey,
    ): string {
        if ($plaintext === '') {
            throw new InvalidArgumentException('Plaintext must not be empty.');
        }
        $this->assertLength($recipientPublicKey, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'recipient public key');
        $this->assertLength($senderPrivateKey, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'sender private key');

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        } catch (RandomException $e) {
            throw new SodiumOperationException('Could not generate nonce.', 0, $e);
        }

        $combined = null;
        try {
            $combined = sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $senderPrivateKey,
                $recipientPublicKey,
            );
            $cipher = sodium_crypto_box($plaintext, $nonce, $combined);
        } catch (SodiumException $e) {
            throw new SodiumOperationException('Authenticated encryption failed.', 0, $e);
        } finally {
            if ($combined !== null) {
                sodium_memzero($combined);
            }
        }

        return Encoding::toBase64($nonce . $cipher);
    }

    public function decryptAuthenticated(
        string $ciphertext,
        string $recipientPrivateKey,
        string $senderPublicKey,
    ): string {
        $this->assertLength($recipientPrivateKey, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'recipient private key');
        $this->assertLength($senderPublicKey, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'sender public key');

        $decoded = Encoding::fromBase64($ciphertext);
        $nonceLen = SODIUM_CRYPTO_BOX_NONCEBYTES;
        $minLen = $nonceLen + SODIUM_CRYPTO_BOX_MACBYTES;
        if (strlen($decoded) < $minLen) {
            throw new DecryptionFailedException('Ciphertext is too short to be valid.');
        }

        $nonce = substr($decoded, 0, $nonceLen);
        $cipher = substr($decoded, $nonceLen);

        $combined = null;
        try {
            $combined = sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $recipientPrivateKey,
                $senderPublicKey,
            );
            $plaintext = sodium_crypto_box_open($cipher, $nonce, $combined);
        } catch (SodiumException $e) {
            throw new SodiumOperationException('Authenticated decryption failed.', 0, $e);
        } finally {
            if ($combined !== null) {
                sodium_memzero($combined);
            }
        }

        if ($plaintext === false) {
            throw new DecryptionFailedException(
                'Decryption failed: wrong keys or tampered ciphertext.',
            );
        }

        return $plaintext;
    }

    private function assertLength(string $value, int $expected, string $what): void
    {
        if (strlen($value) !== $expected) {
            throw new InvalidKeyException(sprintf(
                '%s must be exactly %d bytes; got %d.',
                ucfirst($what),
                $expected,
                strlen($value),
            ));
        }
    }
}
