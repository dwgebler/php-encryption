<?php

declare(strict_types=1);

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\Encoding;
use Gebler\Encryption\Exception\InvalidKeyException;
use Gebler\Encryption\Mac;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class MacTest extends TestCase
{
    private Mac $mac;

    #[\Override]
    protected function setUp(): void
    {
        $this->mac = new Mac();
    }

    public function testGenerateKeyReturns32Bytes(): void
    {
        self::assertSame(SODIUM_CRYPTO_AUTH_KEYBYTES, strlen($this->mac->generateKey()));
    }

    public function testSignAndVerifyRoundTrip(): void
    {
        $key = $this->mac->generateKey();
        $tag = $this->mac->sign('hello', $key);
        self::assertSame(SODIUM_CRYPTO_AUTH_BYTES, strlen(Encoding::fromHex($tag)));
        self::assertTrue($this->mac->verify($tag, 'hello', $key));
    }

    public function testVerifyFailsForTamperedMessage(): void
    {
        $key = $this->mac->generateKey();
        $tag = $this->mac->sign('hello', $key);
        self::assertFalse($this->mac->verify($tag, 'goodbye', $key));
    }

    public function testVerifyFailsForWrongKey(): void
    {
        $key = $this->mac->generateKey();
        $other = $this->mac->generateKey();
        $tag = $this->mac->sign('hello', $key);
        self::assertFalse($this->mac->verify($tag, 'hello', $other));
    }

    public function testSignRejectsEmptyMessage(): void
    {
        $key = $this->mac->generateKey();
        $this->expectException(InvalidArgumentException::class);
        $this->mac->sign('', $key);
    }

    public function testSignRejectsWrongKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->mac->sign('hello', str_repeat("\0", 16));
    }

    public function testVerifyRejectsWrongKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->mac->verify(Encoding::toHex(str_repeat("\0", SODIUM_CRYPTO_AUTH_BYTES)), 'hi', str_repeat("\0", 16));
    }

    public function testVerifyReturnsFalseForWrongTagLength(): void
    {
        $key = $this->mac->generateKey();
        self::assertFalse($this->mac->verify(Encoding::toHex(str_repeat("\0", 8)), 'hello', $key));
    }
}
