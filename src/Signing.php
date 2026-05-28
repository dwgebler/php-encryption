<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\DecryptionFailedException;
use Gebler\Encryption\Exception\InvalidKeyException;
use InvalidArgumentException;

/**
 * Ed25519 digital signatures.
 *
 * Attached: signAttached returns base64(signature || message); openAttached
 * verifies and returns the original message.
 *
 * Detached: signDetached returns hex(signature); verifyDetached checks a
 * (signature, message, public key) triple.
 */
final readonly class Signing
{
    public function generateKeypair(): SigningKeyPair
    {
        $raw = sodium_crypto_sign_keypair();
        return new SigningKeyPair(
            sodium_crypto_sign_publickey($raw),
            sodium_crypto_sign_secretkey($raw),
        );
    }

    public function signAttached(string $message, string $privateKey): string
    {
        if ($message === '') {
            throw new InvalidArgumentException('Message must not be empty.');
        }
        $this->assertLength($privateKey, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'private key');

        return Encoding::toBase64(sodium_crypto_sign($message, $privateKey));
    }

    public function openAttached(string $signedMessage, string $publicKey): string
    {
        if ($signedMessage === '') {
            throw new InvalidArgumentException('Signed message must not be empty.');
        }
        $this->assertLength($publicKey, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'public key');

        $decoded = Encoding::fromBase64($signedMessage);

        $message = sodium_crypto_sign_open($decoded, $publicKey);
        if ($message === false) {
            throw new DecryptionFailedException('Signature verification failed.');
        }

        return $message;
    }

    public function signDetached(string $message, string $privateKey): string
    {
        if ($message === '') {
            throw new InvalidArgumentException('Message must not be empty.');
        }
        $this->assertLength($privateKey, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'private key');

        return Encoding::toHex(sodium_crypto_sign_detached($message, $privateKey));
    }

    public function verifyDetached(string $signature, string $message, string $publicKey): bool
    {
        if ($message === '') {
            throw new InvalidArgumentException('Message must not be empty.');
        }
        $this->assertLength($publicKey, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'public key');

        try {
            $sigBytes = Encoding::fromHex($signature);
        } catch (\InvalidArgumentException) {
            return false;
        }

        if (strlen($sigBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($sigBytes, $message, $publicKey);
    }

    /**
     * @phpstan-assert non-empty-string $value
     */
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
