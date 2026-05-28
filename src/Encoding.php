<?php

declare(strict_types=1);

namespace Gebler\Encryption;

use InvalidArgumentException;
use SodiumException;

/**
 * Timing-safe hex and base64 encoding helpers wrapping the sodium_* variants.
 * All decode methods throw InvalidArgumentException on malformed input.
 */
final class Encoding
{
    public static function toHex(string $bytes): string
    {
        return sodium_bin2hex($bytes);
    }

    public static function fromHex(string $hex): string
    {
        try {
            return sodium_hex2bin($hex);
        } catch (SodiumException $e) {
            throw new InvalidArgumentException('Input is not valid hex.', 0, $e);
        }
    }

    public static function toBase64(string $bytes): string
    {
        return sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    public static function fromBase64(string $base64): string
    {
        try {
            return sodium_base642bin($base64, SODIUM_BASE64_VARIANT_ORIGINAL);
        } catch (SodiumException $e) {
            throw new InvalidArgumentException('Input is not valid base64.', 0, $e);
        }
    }
}
