<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use Gebler\Encryption\Exception\InvalidKeyException;
use InvalidArgumentException;

/**
 * Shared-secret message authentication using HMAC-SHA512-256
 * (`sodium_crypto_auth`). Key is 32 raw bytes; tag is 32 raw bytes,
 * returned hex-encoded (64 chars).
 */
final readonly class Mac
{
    public function generateKey(): string
    {
        return sodium_crypto_auth_keygen();
    }

    public function sign(string $message, string $key): string
    {
        if ($message === '') {
            throw new InvalidArgumentException('Message must not be empty.');
        }
        $this->assertKeyLength($key);

        return Encoding::toHex(sodium_crypto_auth($message, $key));
    }

    public function verify(string $mac, string $message, string $key): bool
    {
        $this->assertKeyLength($key);

        try {
            $tag = Encoding::fromHex($mac);
        } catch (\InvalidArgumentException) {
            return false;
        }

        if (strlen($tag) !== SODIUM_CRYPTO_AUTH_BYTES) {
            return false;
        }

        return sodium_crypto_auth_verify($tag, $message, $key);
    }

    /**
     * @phpstan-assert non-empty-string $key
     */
    private function assertKeyLength(string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'MAC key must be exactly %d bytes; got %d.',
                SODIUM_CRYPTO_AUTH_KEYBYTES,
                strlen($key),
            ));
        }
    }
}
