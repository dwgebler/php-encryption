<?php

use Gebler\Encryption\Encryption;

require_once('vendor/autoload.php');

$crypt = new Encryption();

/**
 * Example 1: Symmetric (anonymous) message authentication.
 */

$message = "This is a message signed anonymously with a secret key.";
$secret = $crypt->generateSigningSecret();
$signature = $crypt->signWithSecret($message, $secret);
$messageAuthenticated = $crypt->verifyWithSecret($signature, $message, $secret);
if ($messageAuthenticated === true) {
    echo "The message has not been tampered with.", PHP_EOL;
}

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

/**
 * Example 2: Asymmetric (identified) message authentication.
 */

$aliceSigningKeypair = $crypt->generateSigningKeypair();
$message = "This is a message signed by Alice.";
$signedMessage = $crypt->getSignedMessage($message, $aliceSigningKeypair['privateKey']);
echo $signedMessage, PHP_EOL;
$verifiedMessage = $crypt->verifySignedMessage($signedMessage, $aliceSigningKeypair['publicKey']);
echo $verifiedMessage, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

/**
 * Example 3: Asymmetric (identified) message signature (detached).
 */

$aliceSigningKeypair = $crypt->generateSigningKeypair();
$message = "This is a message signed by Alice.";
$signature = $crypt->getMessageSignature($message, $aliceSigningKeypair['privateKey']);
$messageAuthenticated = $crypt->verifyMessageSignature($message, $signature, $aliceSigningKeypair['publicKey']);
if ($messageAuthenticated === true) {
    echo "The message has not been tampered with.", PHP_EOL;
}

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

/**
 * Example 4: Symmetric encryption with secret key.
 */

$mySecret = $crypt->generateEncryptionSecret();
$message = "This is a test message.";
$encrypted = $crypt->encryptWithSecret($message, $mySecret);
echo $encrypted, PHP_EOL;
$decrypted = $crypt->decryptWithSecret($encrypted, $mySecret);
echo $decrypted, PHP_EOL;

$mySecret = random_bytes(32);
$message = "This is another test message.";
// Password is raw binary data.
$encrypted = $crypt->encryptWithSecret($message, $mySecret, false);
echo $encrypted, PHP_EOL;
$decrypted = $crypt->decryptWithSecret($encrypted, $mySecret, false);
echo $decrypted, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

/**
 * Example 5: Asymmetric encryption with public key and signed by sender.
 */

$aliceKeypair = $crypt->generateEncryptionKeypair("alice_secret");
$bobKeypair = $crypt->generateEncryptionKeypair("bob_secret");

$message = "Hello Bob! This is a secret message from Alice.";
$encrypted = $crypt->encryptWithKey($message, $bobKeypair['publicKey'], $aliceKeypair['privateKey']);
echo $encrypted, PHP_EOL;

$decrypted = $crypt->decryptWithKey($encrypted, $bobKeypair['privateKey'], $aliceKeypair['publicKey']);
echo $decrypted, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

/**
 * Example 6: Anonymous asymmetric encryption to recipient with public key only.
 */

$bobKeypair = $crypt->generateEncryptionKeypair("bob_secret");
$message = "Hello Bob! This is a secret message from an unknown sender.";
$encrypted = $crypt->encryptWithKey($message, $bobKeypair['publicKey']);
echo $encrypted, PHP_EOL;

$decrypted = $crypt->decryptWithKey($encrypted, $bobKeypair['keypair']);
echo $decrypted, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;
