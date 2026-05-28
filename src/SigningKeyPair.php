<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\InvalidKeyException;

/**
 * Ed25519 keypair (sign). Public key is 32 raw bytes, private key is 64
 * raw bytes.
 */
final readonly class SigningKeyPair
{
    public function __construct(
        public string $publicKey,
        public string $privateKey,
    ) {
        if (strlen($this->publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'Ed25519 public key must be %d bytes; got %d.',
                SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES,
                strlen($this->publicKey),
            ));
        }

        if (strlen($this->privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'Ed25519 private key must be %d bytes; got %d.',
                SODIUM_CRYPTO_SIGN_SECRETKEYBYTES,
                strlen($this->privateKey),
            ));
        }
    }
}
