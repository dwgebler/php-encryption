<?php

declare(strict_types=1);

namespace Gebler\Encryption\Exception;

/**
 * Thrown when an underlying sodium primitive raises SodiumException — the
 * original SodiumException is set as the previous exception.
 */
final class SodiumOperationException extends EncryptionException
{
}
