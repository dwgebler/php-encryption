<?php

declare(strict_types=1);

namespace Gebler\Encryption\Exception;

/**
 * Thrown when a ciphertext fails authenticated decryption: wrong key, wrong
 * password, tampered ciphertext, or invalid MAC. Never reveals which.
 */
final class DecryptionFailedException extends EncryptionException
{
}
