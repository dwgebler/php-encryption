<?php

declare(strict_types=1);

use Gebler\Encryption\Encoding;
use Gebler\Encryption\Encryption;

require_once __DIR__ . '/vendor/autoload.php';

$crypt = new Encryption();

echo "=== 1. Password hashing (for storing user passwords) ===\n";
$pw = $crypt->passwords();
$hash = $pw->hash('correct horse battery staple');
echo "Stored hash: $hash\n";
echo 'Verify correct: ' . var_export($pw->verify('correct horse battery staple', $hash), true) . "\n";
echo 'Verify wrong:   ' . var_export($pw->verify('wrong password', $hash), true) . "\n";

echo "\n=== 2. Symmetric encryption with password ===\n";
$sym = $crypt->symmetric();
$ct = $sym->encryptWithPassword('a secret message', 'password123');
echo "Ciphertext: $ct\n";
echo 'Decrypted:  ' . $sym->decryptWithPassword($ct, 'password123') . "\n";

echo "\n=== 3. Symmetric encryption with 32-byte key ===\n";
$key = $sym->generateKey();
$ct = $sym->encryptWithKey('hello via key', $key);
echo "Ciphertext: $ct\n";
echo 'Decrypted:  ' . $sym->decryptWithKey($ct, $key) . "\n";
echo 'Key as hex: ' . Encoding::toHex($key) . "\n";

echo "\n=== 4. Authenticated asymmetric encryption ===\n";
$asym = $crypt->asymmetric();
$alice = $asym->generateKeypair();
$bob = $asym->generateKeypair();
$ct = $asym->encryptAuthenticated('Hi Bob, it is Alice.', $bob->publicKey, $alice->privateKey);
echo "Ciphertext: $ct\n";
echo 'Decrypted:  ' . $asym->decryptAuthenticated($ct, $bob->privateKey, $alice->publicKey) . "\n";

echo "\n=== 5. Anonymous asymmetric encryption ===\n";
$ct = $asym->encryptAnonymous('Anonymous tip for Bob.', $bob->publicKey);
echo "Ciphertext: $ct\n";
echo 'Decrypted:  ' . $asym->decryptAnonymous($ct, $bob) . "\n";

echo "\n=== 6. Attached Ed25519 signature ===\n";
$signing = $crypt->signing();
$signer = $signing->generateKeypair();
$signed = $signing->signAttached('a public statement', $signer->privateKey);
echo "Signed:  $signed\n";
echo 'Opened:  ' . $signing->openAttached($signed, $signer->publicKey) . "\n";

echo "\n=== 7. Detached Ed25519 signature ===\n";
$signature = $signing->signDetached('a public statement', $signer->privateKey);
echo "Signature: $signature\n";
echo 'Valid:     ' . var_export(
    $signing->verifyDetached($signature, 'a public statement', $signer->publicKey),
    true,
) . "\n";

echo "\n=== 8. Shared-secret MAC ===\n";
$mac = $crypt->mac();
$macKey = $mac->generateKey();
$tag = $mac->sign('a message', $macKey);
echo "Tag:   $tag\n";
echo 'Valid: ' . var_export($mac->verify($tag, 'a message', $macKey), true) . "\n";
