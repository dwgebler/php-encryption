<?php

declare(strict_types=1);

namespace Gebler\Encryption\Exception;

use InvalidArgumentException;

/**
 * Thrown when a key, signature, or other binary input does not match the
 * required length or shape.
 */
final class InvalidKeyException extends InvalidArgumentException
{
}
