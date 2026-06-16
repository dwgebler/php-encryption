# Upgrading from 1.x to 2.0

2.0 is a clean break. All public methods of the 1.x `Encryption` class have
been removed, renamed, or moved to dedicated primitive classes accessed via
a facade. There are no backwards-compatibility aliases.

## Security advisory

**If your application stored the output of 1.x `Encryption::hashPassword()` as
a password hash, those stored values offer essentially no protection against
offline brute-force attack.** `hashPassword()` in 1.x computed a single
unsalted BLAKE2b hash, which is fast and deterministic — equivalent in
strength to a single round of SHA-256 from an attacker's perspective.
(Note this was never a documented/recommended use of the function; its usage was intended as a way to create a deterministic length password for use with symmetric encryption, from a shorter or indeterminate length password)

There is no safe in-place migration without the plaintext. **On the user's
next successful login, re-hash their password using the new
`PasswordHasher::hash()` and overwrite the stored value.**

This advisory is also tracked as a GitHub Security Advisory against
versions ≤ 1.1.0.

## Other breaking changes

- **Keys at the API boundary are now raw bytes**, not hex strings. There is
  no `$keyIsHex` flag. Convert at the call site using `Encoding::fromHex()`.
- **No more silent short-key stretching.** Wrong-length keys throw
  `InvalidKeyException`.
- **Password-seeded keypair generation removed.** `generateEncryptionKeypair`
  and `generateSigningKeypair` no longer accept a password parameter. The
  feature was insecure for weak passwords. If you genuinely need
  deterministic keypairs, derive a seed yourself using Argon2id.
- **Asymmetric encryption split into explicit methods.** `decryptWithKey`
  no longer overloads one parameter as either a full keypair or a private
  key — use `decryptAnonymous(string, KeyPair)` or
  `decryptAuthenticated(string, $recipientPrivateKey, $senderPublicKey)`.
- **Exception types changed.** All runtime crypto failures throw
  `Gebler\Encryption\Exception\EncryptionException` or subclasses.
  Catch this base class to handle everything.
- **`require php` is now `^8.2`.** PHP 7.x is no longer supported.

## Method mapping

```
1.x                                       → 2.0
────────────────────────────────────────────────────────────────────────────
$crypt->hashPassword($pw)                 $crypt->passwords()->hash($pw)
                                          ⚠ Returns an Argon2id verifier
                                          string, not a hex BLAKE2b. Use
                                          $crypt->passwords()->verify()
                                          to check.

$crypt->encryptWithPassword($d, $pw)      $crypt->symmetric()->encryptWithPassword($d, $pw)
$crypt->decryptWithPassword($c, $pw)      $crypt->symmetric()->decryptWithPassword($c, $pw)

$crypt->encryptWithSecret($d, $hexKey)    $key = Encoding::fromHex($hexKey);
                                          $crypt->symmetric()->encryptWithKey($d, $key)
                                          ⚠ Key must be exactly 32 raw bytes.

$crypt->decryptWithSecret($c, $hexKey)    $key = Encoding::fromHex($hexKey);
                                          $crypt->symmetric()->decryptWithKey($c, $key)

$crypt->generateEncryptionSecret()        Encoding::toHex(
                                              $crypt->symmetric()->generateKey()
                                          )

$crypt->encryptWithKey($d, $pubHex)       $crypt->asymmetric()->encryptAnonymous(
                                              $d, Encoding::fromHex($pubHex)
                                          )

$crypt->encryptWithKey($d, $pubHex, $privHex)
                                          $crypt->asymmetric()->encryptAuthenticated(
                                              $d,
                                              Encoding::fromHex($pubHex),
                                              Encoding::fromHex($privHex),
                                          )

$crypt->decryptWithKey($c, $keypairHex)   // Anonymous (1.x passed combined hex):
                                          $crypt->asymmetric()->decryptAnonymous(
                                              $c,
                                              new KeyPair(
                                                  Encoding::fromHex($pubHex),
                                                  Encoding::fromHex($privHex),
                                              ),
                                          )

$crypt->decryptWithKey($c, $privHex, $pubHex)
                                          $crypt->asymmetric()->decryptAuthenticated(
                                              $c,
                                              Encoding::fromHex($privHex),
                                              Encoding::fromHex($pubHex),
                                          )

$crypt->generateEncryptionKeypair()       $crypt->asymmetric()->generateKeypair()
                                          // Returns a KeyPair value object
                                          // with publicKey/privateKey as raw bytes.

$crypt->generateEncryptionKeypair($pw)    REMOVED — feature was unsafe.
                                          Derive a seed yourself with Argon2id
                                          if you need determinism.

$crypt->generateSigningKeypair()          $crypt->signing()->generateKeypair()
                                          // Returns a SigningKeyPair.

$crypt->generateSigningKeypair($pw)       REMOVED — same reason.

$crypt->getSignedMessage($m, $privHex)    $crypt->signing()->signAttached(
                                              $m, Encoding::fromHex($privHex)
                                          )
$crypt->verifySignedMessage($s, $pubHex)  $crypt->signing()->openAttached(
                                              $s, Encoding::fromHex($pubHex)
                                          )
$crypt->getMessageSignature($m, $privHex) $crypt->signing()->signDetached(
                                              $m, Encoding::fromHex($privHex)
                                          )
$crypt->verifyMessageSignature($m, $s, $pubHex)
                                          $crypt->signing()->verifyDetached(
                                              $s, $m, Encoding::fromHex($pubHex)
                                          )
                                          ⚠ Argument order is
                                          (signature, message, publicKey).

$crypt->signWithSecret($m, $hexKey)       $crypt->mac()->sign(
                                              $m, Encoding::fromHex($hexKey)
                                          )
$crypt->verifyWithSecret($mac, $m, $hexKey)
                                          $crypt->mac()->verify(
                                              $mac, $m, Encoding::fromHex($hexKey)
                                          )
$crypt->generateSigningSecret()           Encoding::toHex($crypt->mac()->generateKey())
```

### Note on the asymmetric `KeyPair` migration

If your 1.x code passed `$keypairHex` (the combined keypair blob) to
`decryptWithKey`, you almost certainly stored it from the
`generateEncryptionKeypair()` return — that function returned an array with
three fields: `publicKey`, `privateKey`, and `keypair` (the combined blob).
The 2.0 `KeyPair` value object takes the `publicKey` and `privateKey`
fields directly:

```php
new KeyPair(
    Encoding::fromHex($oldArray['publicKey']),
    Encoding::fromHex($oldArray['privateKey']),
)
```

If you only stored the combined `keypair` blob, the public key is the last
32 bytes and the private key is the first 32 bytes (sodium's
`crypto_box_keypair()` layout):

```php
$combined = Encoding::fromHex($keypairHex);
$privateKey = substr($combined, 0, SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
$publicKey  = substr($combined, SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
new KeyPair($publicKey, $privateKey);
```
