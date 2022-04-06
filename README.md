# PHP Encryption

![Build Status!](https://app.travis-ci.com/dwgebler/php-encryption.svg?token=uj4HfXm5wqJXVuPAd984&branch=master)

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
composer require dwgebler/encryption
```

## Usage

For a quick start, see the included `demo.php` file.

Create an instance of the Encryption class.

```php
<?php
    use Gebler\Encryption\Encryption;
    
    $crypt = new Encryption();
```

### Symmetric Encryption

Use the function `encryptWithSecret(string $message, string $password, bool $hexEncoded = true)` to encrypt a message with a secret key.
This function expects the message or data to be encrypted as a string, and the secret key as a hexadecimal string.
If your secret is not a hexadecimal encoded, you can pass `false` as the third parameter to indicate that the secret is not encoded.

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

    // Alternatively, create a key and encode it as hex.
    // Keys should be 32 bytes long - shorter keys are forced to this length by a deterministic hash,
    // but this is not recommended. Longer keys will throw an InvalidArgumentException.
    $mySecret = bin2hex("my_super_secret_key");
    // ...or use random_bytes() to generate a random key.
    $mySecret = bin2hex(random_bytes(32));
    $result = $crypt->encryptWithSecret($data, $mySecret);
    
    // Or, pass in a raw binary key by setting the `hex` parameter to false.
    $mySecret = random_bytes(32);
    $result = $crypt->encryptWithSecret($data, $mySecret, false);
    // $result is now base64 encoded, e.g.
    echo $result;
    // wgYwuB/by9bz+CvHj1EtylicXnRH6hl9hLALsUUPUHaZeO3sEj4hgi8+pKBZGZIG6ueRKw3xpvrG8dRWU9OCn3aMtlwLz8aapUX/oK3L 
```

To decrypt your message, use the function `decryptWithSecret()`.

```php
    $mySecret = "my_super_secret_key";
    $message = "This is a test message.";
    $encrypted = $crypt->encryptWithSecret($message, $mySecret, false);
    echo $encrypted, PHP_EOL;
    $decrypted = $crypt->decryptWithSecret($encrypted, $mySecret, false);
    echo $decrypted, PHP_EOL;
```

### Asymmetric Encryption

To carry out authenticated asymmetric encryption (i.e. where the message is both encrypted and the sender of the message can be verified), you need to generate a public and private key pair for the sender.
You will also need the public key of the recipient.

```php
    // Generate a new random keypair.
    $keypair = $crypt->generateEncryptionKeypair();
    // Or provide a password to generate a deterministic keypair.
    $keypair = $crypt->generateEncryptionKeypair("my_super_secret_password");
    // Or use a pre-existing keypair.
    
    // Once you have a keypair, you can export the public key as a hexadecimal string,
    // for storage or transmission.
    $publicKey = $keypair['publicKey'];
    
    // The keypair also includes the private key.
    $privateKey = $keypair['privateKey'];    

    // The full keypair is also provided. This is a string containing both the private and public key.
    $fullKeypair = $keypair['keypair'];
```

As an example, let's encrypt a message from Alice to Bob.

```php
    $aliceKeypair = $crypt->generateEncryptionKeypair("alice_secret");
    // In the real-world, Bob has provided Alice with his public key, but for demo purposes
    // we'll generate a keypair for him too.
    $bobKeypair = $crypt->generateEncryptionKeypair("bob_secret");
    
    // Alice encrypts a message for Bob, using his public key and her private key.
    $message = "Hello Bob! This is a secret message from Alice.";
    $encrypted = $crypt->encryptWithKey($message, $bobKeypair['publicKey'], $aliceKeypair['privateKey']);
    // Alice can now transmit $encrypted to Bob. It will look something like this:
    // hMvdJf2L78ZWcF38WRXJ16q3xXnlsWWfOsbJISPVwJhBtdcWbZ8SquS3oyJD1k6H/lAs+VHXPpDNfYLWO3wMLl+FB8rYUyCe+IZzti3dFL0YljeJ3QreGlrv
    echo $encrypted, PHP_EOL;
    
    // Bob decrypts the message using his private key and the public key of Alice.
    $decrypted = $crypt->decryptWithKey($encrypted, $bobKeypair['privateKey'], $aliceKeypair['publicKey']);
    // Hello Bob! This is a secret message from Alice.
    echo $decrypted, PHP_EOL;
```

You can also use this library to carry out anonymous asymmetric encryption, using only the public key of the 
recipient. In this case, the sender's private key is not required and although only the recipient (the holder of the corresponding private key) can decode the message,
they cannot identify or authenticate the sender. This is similar to `openssl_public_encrypt `.

```php
    $bobKeypair = $crypt->generateEncryptionKeypair("bob_secret");
    // Alice encrypts a message for Bob, using his public key.
    $message = "Hello Bob! This is a secret message from an unknown sender.";
    $encrypted = $crypt->encryptWithKey($message, $bobKeypair['publicKey']);
    // Alice can now transmit $encrypted to Bob.
    echo $encrypted, PHP_EOL;
    
    // Bob decrypts the message using his full keypair.
    $decrypted = $crypt->decryptWithKey($encrypted, $bobKeypair['keypair']);
    // Hello Bob! This is a secret message from an unknown sender.
    echo $decrypted, PHP_EOL;
```

### Digital Signing

Asymmetric encryption is useful for securing messages, but it is also useful for authenticating the sender of a message.

Digital signatures are a way to authenticate the sender of a message, as well the message itself, ensuring it 
has not been tampered with or altered during transmission.

```php
    // Generate a new random keypair.
    // Like generateEncryptionKeypair, you can also optionally provide a password to generate a deterministic keypair.
    $aliceSigningKeypair = $crypt->generateSigningKeypair();
    
    // Alice signs a message for Bob, using her private key.
    $message = "This is a message signed by Alice.";
    $signedMessage = $crypt->getSignedMessage($message, $aliceSigningKeypair['privateKey']);
    // Alice can now transmit $signedMessage to Bob. It will look something like this:
    // JaI6p6jb5qQ041DiK1Yqbk8u1r/wVAovzy57ELfwrWfhqLCUU9jTzBLH6K6v1VF/8vOxaOZe2r8ch/GUKmfgC1RoaXMgaXMgYSBtZXNzYWdlIHNpZ25lZCBieSBBbGljZS4=
    // Note: The message itself is NOT encrypted and can be viewed by anyone, by decoding the base64-encoded signed message.
    echo $signedMessage, PHP_EOL;
    
    // Bob can now use Alice's public key to verify the signature and obtain the message part.
    // If the message has been tampered with, the signature will be invalid and the message will be rejected.
    $verifiedMessage = $crypt->verifySignedMessage($signedMessage, $aliceSigningKeypair['publicKey']);
    // This is a message signed by Alice.
    echo $verifiedMessage, PHP_EOL;
    
```

We can also generate a signature for a message without attaching it to the message itself.

```php
    $aliceSigningKeypair = $crypt->generateSigningKeypair();
    
    // Alice signs a message for Bob, using her private key.
    $message = "This is a message signed by Alice.";
    $signature = $crypt->getMessageSignature($message, $aliceSigningKeypair['privateKey']);
    
    // Alice can now transmit the message and signature separately to Bob.
    // Bob can now use Alice's public key to verify the signature.
    // If the message has been tampered with, the signature will be invalid and the message will be rejected.
    $messageAuthenticated = $crypt->verifyMessageSignature($message, $signature, $aliceSigningKeypair['publicKey']);
    if ($messageAuthenticated === true) {
        echo "The message has not been tampered with.", PHP_EOL;
    } 
```

### Message Authentication

Instead of asymmetric keys, we can also use a shared secret to generate a Message Authentication Code (MAC) 
and use this to sign and authenticate messages.

```php
    $message = "This is a message signed anonymously with a secret key.";
    // We can generate a secure, random 32 byte key, which is returned as a hexadecimal string.
    $secret = $crypt->generateSigningSecret();
    // Or, as long as the key is 32 bytes (256 bits), you can use any other string.
    $secret = hash("sha256", "my secret key");
    
    // Like with the symmetric encryption functions, you can pass an optional third parameter
    // to signWithSecret to specify that the secret key is NOT a hexadecimal string.
    $secret = hash("sha256", "my secret key", true);
    $signature = $crypt->signWithSecret($message, $secret, false);

    // Or omit this parameter if the secret is a hexadecimal string.
    $secret = $crypt->generateSigningSecret();
    $signature = $crypt->signWithSecret($message, $secret);
    
    // The message can now be either transmitted to someone else who also has the shared secret,
    // or later verified on the same system, e.g. after being retrieved from a database.
    $messageAuthenticated = $crypt->verifyWithSecret($signature, $message, $secret);
    
    if ($messageAuthenticated === true) {
        echo "The message has not been tampered with.", PHP_EOL;
    }
    
    // Similarly, pass false as the third parameter if the secret is NOT a hexadecimal string.
    $secret = hash("sha256", "my secret key", true);
    $signature = $crypt->signWithSecret($message, $secret, false);
    $messageAuthenticated = $crypt->verifyWithSecret($signature, $message, $secret, false);
    if ($messageAuthenticated === true) {
        echo "The message has not been tampered with.", PHP_EOL;
    }       
```

### Licence

This software is released under the [MIT License](https://opensource.org/licenses/MIT).

### Bugs, questions, comments

Please raise a GitHub issue if you encounter any problems or have any questions.

