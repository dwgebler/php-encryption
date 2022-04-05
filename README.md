# PHP Encryption
A cryptography API wrapping the Sodium library, providing a simple object interface for symmetrical and asymmetrical encryption, decryption, digital signing and message authentication.

The `Encryption` class is able to generate secrets and keypairs, encrypt and decrypt data, sign and verify data, and generate and verify digital signatures.

Encrypted messages are returned base64 encoded, while keys and secrets are returned as hexadecimal strings.

The transformation of these to and from binary data makes use of the `sodium_*` timing-safe functions.

All underlying cryptography is performed using the [Sodium](https://www.php.net/manual/en/book.sodium.php) library.

This library requires PHP 7.2 or higher with `libsodium` installed (this is bundled with PHP 7.2 or above, 
so you probably already have it).

## Installation

Install via Composer

```bash
composer require dwgebler/php-encryption
```

## Usage

Create an instance of the Encryption class.

```php
<?php
    use Gebler\Encryption\Encryption;
    
    $crypt = new Encryption();
```

### Symmetric Encryption

Use the function `encryptWithSecret()` to encrypt a message with a secret key.

You can either generate a secret key with `generateSecret()` or use a pre-existing one.

Alternatively, you can pass in a reference to a null or empty string to generate a secret key.

```php
    $mySecret = null;
    $data = "Hello world! This is a secret message.";
    $result = $crypt->encryptWithSecret($data, $mySecret);
    // $mySecret has now been populated with a new secret key

    // Alternatively, generate a new key.
    $mySecret = $crypt->generateEncryptionSecret();
    $result = $crypt->encryptWithSecret($data, $mySecret);

    // Alternatively, create a key with random_bytes() etc. and encode it as hex.
    $mySecret = bin2hex(random_bytes(32));
    $result = $crypt->encryptWithSecret($data, $mySecret);
    
    // Or, pass in a raw binary key by setting the `hex` parameter to false.
    $mySecret = random_bytes(32);
    $result = $crypt->encryptWithSecret($data, $mySecret, false);
    // $result is now base64 encoded, e.g.
    // wgYwuB/by9bz+CvHj1EtylicXnRH6hl9hLALsUUPUHaZeO3sEj4hgi8+pKBZGZIG6ueRKw3xpvrG8dRWU9OCn3aMtlwLz8aapUX/oK3L 
```

### Asymmetric Encryption

```php
```

### Digital Signing

```php
```

### Message Authentication

```php
```

