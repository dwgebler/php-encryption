<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\Encoding;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class EncodingTest extends TestCase
{
    public function testToHexRoundTrip(): void
    {
        $bytes = random_bytes(32);
        $hex = Encoding::toHex($bytes);
        self::assertSame(64, strlen($hex));
        self::assertSame($bytes, Encoding::fromHex($hex));
    }

    public function testToBase64RoundTrip(): void
    {
        $bytes = random_bytes(48);
        $b64 = Encoding::toBase64($bytes);
        self::assertSame($bytes, Encoding::fromBase64($b64));
    }

    public function testFromHexRejectsNonHex(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Encoding::fromHex('not-hex-data!');
    }

    public function testFromBase64RejectsNonBase64(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Encoding::fromBase64('@@@@not base64@@@@');
    }

    public function testToHexEmptyString(): void
    {
        self::assertSame('', Encoding::toHex(''));
        self::assertSame('', Encoding::fromHex(''));
    }

    public function testToBase64EmptyString(): void
    {
        self::assertSame('', Encoding::toBase64(''));
        self::assertSame('', Encoding::fromBase64(''));
    }
}
