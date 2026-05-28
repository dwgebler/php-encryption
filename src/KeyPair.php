<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\InvalidKeyException;

/**
 * X25519 keypair (curve25519 box). Public key is 32 raw bytes, private key
 * is 32 raw bytes.
 */
final readonly class KeyPair
{
    public function __construct(
        public string $publicKey,
        public string $privateKey,
    ) {
        if (strlen($this->publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'X25519 public key must be %d bytes; got %d.',
                SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
                strlen($this->publicKey),
            ));
        }

        if (strlen($this->privateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'X25519 private key must be %d bytes; got %d.',
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES,
                strlen($this->privateKey),
            ));
        }
    }
}
