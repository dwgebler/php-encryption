<?php

use Gebler\Encryption\Encryption;

require_once('vendor/autoload.php');

$crypt = new Encryption();

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

$data = "Hello world! This is a secret message.";
$result = $crypt->encryptWithSecret($data, $mySecret);
echo "Encrypted data: ", $result, PHP_EOL;
echo $mySecret, PHP_EOL;
$decrypted = $crypt->decryptWithSecret($result, $mySecret);
echo "Decrypted data: ", $decrypted, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;


$key = $crypt->generateEncryptionSecret();

$data = 'Hello World! This is a secret message.';

$result = $crypt->encryptWithSecret($data, $key);

echo $result, PHP_EOL;

//echo $crypt->decryptWithSecret($result, hex2bin($keyHex)), PHP_EOL;
echo $crypt->decryptWithSecret($result, $key), PHP_EOL;

$hash = sodium_bin2hex(sodium_crypto_generichash("Some password", "", 32));
echo $hash, PHP_EOL;

var_dump($hash === 'd817c88db153f90ce9a93bdbd0b9319137b6e673bd0abf7ca5a6ceeb53cadc97');

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

$key = random_bytes(32);
$data = json_encode(['message' => 'Hello World! This is a different secret message.']);
$result = $crypt->encryptWithSecret($data, $key, false);
echo $result, PHP_EOL;
echo $crypt->decryptWithSecret($result, $key, false), PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

$data = "Hello, this is a secret message from Alice to Bob.";
$aliceKeypair = $crypt->generateEncryptionKeypair();
$bobKeypair = $crypt->generateEncryptionKeypair();

$result = $crypt->encryptWithKey($data, $bobKeypair['publicKey'], $aliceKeypair['privateKey']);
echo $result, PHP_EOL;
$decrypted = $crypt->decryptWithKey($result, $bobKeypair['privateKey'], $aliceKeypair['publicKey']);
echo $decrypted, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;

$data = "Hello, this is a secret message to Alice, unauthenticated.";
$result = $crypt->encryptWithKey($data, $aliceKeypair['publicKey']);
echo $result, PHP_EOL;
$decrypted = $crypt->decryptWithKey($result, $aliceKeypair['keypair']);
echo $decrypted, PHP_EOL;

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;
$aliceSigningKey = $crypt->generateSigningKeypair();
$bobSigningKey = $crypt->generateSigningKeypair();

$data = "Hello, this is a message which is signed by Bob.";
$signedMessage = $crypt->getSignedMessage($data, $bobSigningKey['privateKey']);
echo $signedMessage, PHP_EOL;
$verifiedMessage = $crypt->verifySignedMessage($signedMessage, $bobSigningKey['publicKey']);
var_dump($verifiedMessage);
try {
    $verifiedMessage = $crypt->verifySignedMessage($signedMessage, $aliceSigningKey['publicKey']);
} catch (RuntimeException $e) {
    echo $e->getMessage(), PHP_EOL;
}

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;
$data = "Hello, this is a message which is signed by Bob.";
$signature = $crypt->getMessageSignature($data, $bobSigningKey['privateKey']);
echo $signature, PHP_EOL;
$verified = $crypt->verifyMessageSignature($data, $signature, $bobSigningKey['publicKey']);
var_dump($verified);
$verified = $crypt->verifyMessageSignature($data, $signature, $aliceSigningKey['publicKey']);
var_dump($verified);

echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;
$data = "Hello, this is a message signed with a shared secret.";
$secret = $crypt->generateEncryptionSecret();
$signature = $crypt->signWithSecret($data, $secret);
echo $signature, PHP_EOL;
$verified = $crypt->verifyWithSecret($signature, $data, $secret);
var_dump($verified);
echo PHP_EOL,"-------------------------------------------------------",PHP_EOL;
