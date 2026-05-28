# php-encryption

A small PHP wrapper around libsodium, providing focused classes for
password hashing, symmetric encryption, asymmetric encryption, digital
signing, and message authentication.

**Upgrading from 1.x?** See [UPGRADE-2.0.md](UPGRADE-2.0.md) — 2.0 is a
clean break that fixes several security issues, including a critical issue
with 1.x `hashPassword()`. **Read the security advisory at the top of
UPGRADE-2.0.md if you stored 1.x password hashes.**

## Requirements

- PHP 8.2 or higher
- `ext-sodium` (bundled with PHP since 7.2)

## Installation

```bash
composer require dwgebler/encryption
```

## Quick start

```php
use Gebler\Encryption\Encryption;

$crypt = new Encryption();
```

The `Encryption` object is a facade — call accessors to reach each
primitive:

```php
$crypt->passwords();   // PasswordHasher
$crypt->symmetric();   // SymmetricCrypto
$crypt->asymmetric();  // AsymmetricCrypto
$crypt->signing();     // Signing
$crypt->mac();         // Mac
```

Keys at the API boundary are **raw bytes**. Use the `Encoding` helper to
convert between raw bytes and hex / base64 when persisting or transmitting
keys.

## Password hashing (for storing user passwords)

```php
$pw = $crypt->passwords();

$hash = $pw->hash('correct horse battery staple');
// Store $hash in your database.

if ($pw->verify($userInput, $hash)) {
    // login succeeded
    if ($pw->needsRehash($hash)) {
        $hash = $pw->hash($userInput);
        // update stored hash
    }
}
```

Uses Argon2id with `OPSLIMIT_MODERATE` / `MEMLIMIT_MODERATE` by default.
Configure stronger or weaker parameters via the constructor:

```php
use Gebler\Encryption\PasswordHasher;

$pw = new PasswordHasher(
    PasswordHasher::OPSLIMIT_SENSITIVE,
    PasswordHasher::MEMLIMIT_SENSITIVE,
);
```

## Symmetric encryption

### With a password (Argon2id-derived key)

```php
$sym = $crypt->symmetric();

$ciphertext = $sym->encryptWithPassword('secret message', 'a strong password');
$plaintext  = $sym->decryptWithPassword($ciphertext, 'a strong password');
```

### With a 32-byte key

```php
use Gebler\Encryption\Encoding;

$sym = $crypt->symmetric();

$key = $sym->generateKey();              // 32 raw bytes
$keyHex = Encoding::toHex($key);         // store this

// later:
$key = Encoding::fromHex($keyHex);
$ciphertext = $sym->encryptWithKey('secret', $key);
$plaintext  = $sym->decryptWithKey($ciphertext, $key);
```

Wrong-length keys throw `InvalidKeyException`. There is no silent stretching.

## Asymmetric encryption

```php
$asym = $crypt->asymmetric();
$alice = $asym->generateKeypair();
$bob   = $asym->generateKeypair();
```

### Authenticated (Alice → Bob, both identified)

```php
$ciphertext = $asym->encryptAuthenticated(
    'Hi Bob, it is Alice.',
    $bob->publicKey,
    $alice->privateKey,
);

$plaintext = $asym->decryptAuthenticated(
    $ciphertext,
    $bob->privateKey,
    $alice->publicKey,
);
```

### Anonymous (sender hidden)

```php
$ciphertext = $asym->encryptAnonymous('Anonymous tip.', $bob->publicKey);
$plaintext  = $asym->decryptAnonymous($ciphertext, $bob);
```

## Digital signatures (Ed25519)

```php
$signing = $crypt->signing();
$alice = $signing->generateKeypair();
```

### Attached signature

```php
$signed = $signing->signAttached('a public statement', $alice->privateKey);
$original = $signing->openAttached($signed, $alice->publicKey);
```

### Detached signature

```php
$signature = $signing->signDetached('a public statement', $alice->privateKey);
$valid = $signing->verifyDetached($signature, 'a public statement', $alice->publicKey);
```

## Message authentication (shared secret)

```php
$mac = $crypt->mac();
$key = $mac->generateKey();

$tag = $mac->sign('a message', $key);
$ok  = $mac->verify($tag, 'a message', $key); // true
```

## Exceptions

The library uses two distinct exception trees:

**`Gebler\Encryption\Exception\EncryptionException`** (extends `RuntimeException`)
— runtime crypto failures. Catch this base type to handle any cipher /
signature failure at once.

| Subclass | Thrown when |
|---|---|
| `DecryptionFailedException` | Wrong key, wrong password, tampered ciphertext, signature verification failure |
| `SodiumOperationException` | Underlying sodium primitive raised `SodiumException` |

**`\InvalidArgumentException`** — input-shape errors (programmer mistakes
detectable at the call site, separate from crypto failures):

| Exception | Thrown when |
|---|---|
| `Gebler\Encryption\Exception\InvalidKeyException` | Key or signature has wrong length |
| `\InvalidArgumentException` (directly) | Plaintext / message is empty |

To handle everything, catch both `EncryptionException` and
`\InvalidArgumentException`.

## License

MIT.
