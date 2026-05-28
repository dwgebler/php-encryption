<?php

declare(strict_types=1);

namespace Gebler\Encryption\Exception;

use RuntimeException;

/**
 * Base exception for all runtime cryptographic failures in this library.
 * Catch this type to handle any crypto error without caring about the
 * specific cause.
 */
class EncryptionException extends RuntimeException
{
}
