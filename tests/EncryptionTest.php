<?php

namespace Gebler\Encryption\Tests;

use Gebler\Encryption\Encryption;
use PHPUnit\Framework\TestCase;

class EncryptionTest extends TestCase
{
    /**
     * @var Encryption
     */
    private $crypt;

    public function setUp(): void
    {
        parent::setUp();
        $this->crypt = new Encryption();
    }

    private function isBase64Encoded($string)
    {
        return (bool) preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $string);
    }

    public function testEncryptWithPasswordReturnsEncryptedDataBase64String()
    {
        $message = 'This is a test message';
        $encrypted = $this->crypt->encryptWithPassword($message, 'password');
        $this->assertTrue($this->isBase64Encoded($encrypted));
        $this->assertNotEquals($message, base64_decode($encrypted));
    }

    public function testDecryptWithPasswordReturnsDecryptedMessage()
    {
        $message = 'This is a test message';
        $encrypted = $this->crypt->encryptWithPassword($message, 'password');
        $decrypted = $this->crypt->decryptWithPassword($encrypted, 'password');
        $this->assertEquals($message, $decrypted);
    }

    public function testDecryptWithPasswordThrowsExceptionOnInvalidPassword()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not decrypt data');
        $message = 'This is a test message';
        $encrypted = $this->crypt->encryptWithPassword($message, 'password');
        $decrypted = $this->crypt->decryptWithPassword($encrypted, 'wrong password');
    }

    public function testDecryptWithSecretReturnsDecryptedMessageWithCorrectSecret()
    {
        $secret = bin2hex(random_bytes(32));
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithSecret($message, $secret);
        $decrypted = $this->crypt->decryptWithSecret($encrypted, $secret);
        $this->assertEquals($message, $decrypted);
    }

    public function testEncryptWithSecretReturnsBase64EncryptedMessage()
    {
        $secret = bin2hex(random_bytes(32));
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithSecret($message, $secret);
        $this->assertNotEquals($message, base64_decode($encrypted));
        $this->assertTrue($this->isBase64Encoded($encrypted));
    }

    public function testDecryptWithSecretThrowsInvalidArgumentExceptionOnInvalidSecret()
    {
        $secret = bin2hex(random_bytes(32));
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithSecret($message, $secret);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Could not decrypt data; probably the wrong password');
        $this->crypt->decryptWithSecret($encrypted, bin2hex(random_bytes(32)));
    }

    public function testDecryptWithSecretThrowsRuntimeExceptionOnInvalidHexSecret()
    {
        $secret = bin2hex(random_bytes(32));
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithSecret($message, $secret);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not decrypt data; probably password wrong format');
        $this->crypt->decryptWithSecret($encrypted, 'not-hex');
    }

    public function testEncryptWithSecretPopulatesRandomKeyWhenNotProvided()
    {
        $key = null;
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithSecret($message, $key);
        $decrypted = $this->crypt->decryptWithSecret($encrypted, $key);
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, strlen(hex2bin($key)));
        $this->assertEquals($message, $decrypted);
    }

    public function testEncryptWithSecretThrowsInvalidArgumentExceptionOnInvalidMessage()
    {
        $secret = bin2hex(random_bytes(32));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Data to encrypt cannot be empty.');
        $this->crypt->encryptWithSecret('', $secret);
    }

    public function testEncryptWithKeyReturnsBase64EncryptedMessage()
    {
        $key = $this->crypt->generateEncryptionKeypair('secret_password');
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithKey($message, $key['publicKey']);
        $this->assertNotEquals($message, base64_decode($encrypted));
        $this->assertTrue($this->isBase64Encoded($encrypted));
    }

    public function testDecryptWithKeyReturnsDecryptedMessageWithCorrectKey()
    {
        $key = $this->crypt->generateEncryptionKeypair('secret_password');
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithKey($message, $key['publicKey']);
        $decrypted = $this->crypt->decryptWithKey($encrypted, $key['keypair']);
        $this->assertEquals($message, $decrypted);
    }

    public function testDecryptWithKeyWithRecipientAndSenderKeyReturnsDecryptedMessageWithCorrectKey()
    {
        $senderKeypair = $this->crypt->generateEncryptionKeypair('secret_password');
        $recipientKeypair = $this->crypt->generateEncryptionKeypair('other_secret_password');
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithKey($message, $recipientKeypair['publicKey'], $senderKeypair['privateKey']);
        $decrypted = $this->crypt->decryptWithKey($encrypted, $recipientKeypair['privateKey'], $senderKeypair['publicKey']);
        $this->assertNotEquals($message, base64_decode($encrypted));
        $this->assertEquals($message, $decrypted);
    }

    public function testDecryptWithKeyWithRecipientAndSenderKeyThrowsExceptionWithIncorrectPrivateKey()
    {
        $senderKeypair = $this->crypt->generateEncryptionKeypair('secret_password');
        $recipientKeypair = $this->crypt->generateEncryptionKeypair('other_secret_password');
        $otherKeypair = $this->crypt->generateEncryptionKeypair('different_secret_password');
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithKey($message, $recipientKeypair['publicKey'], $senderKeypair['privateKey']);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Decryption failed.');
        $this->crypt->decryptWithKey($encrypted, $otherKeypair['privateKey'], $senderKeypair['publicKey']);
    }

    public function testDecryptWithKeyWithRecipientAndSenderKeyThrowsExceptionWithIncorrectPublicKey()
    {
        $senderKeypair = $this->crypt->generateEncryptionKeypair('secret_password');
        $recipientKeypair = $this->crypt->generateEncryptionKeypair('other_secret_password');
        $otherKeypair = $this->crypt->generateEncryptionKeypair('different_secret_password');
        $message = 'Hello World, I am a secret message!';
        $encrypted = $this->crypt->encryptWithKey($message, $recipientKeypair['publicKey'], $senderKeypair['privateKey']);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Decryption failed.');
        $this->crypt->decryptWithKey($encrypted, $recipientKeypair['privateKey'], $otherKeypair['publicKey']);
    }

    public function testGenerateEncryptionKeypairReturnsArrayWithHexEncodedKeys()
    {
        $keypair = $this->crypt->generateEncryptionKeypair('secret_password');
        $this->assertEquals(SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, strlen(hex2bin($keypair['publicKey'])));
        $this->assertEquals(SODIUM_CRYPTO_BOX_SECRETKEYBYTES, strlen(hex2bin($keypair['privateKey'])));
        $this->assertEquals(SODIUM_CRYPTO_BOX_KEYPAIRBYTES, strlen(hex2bin($keypair['keypair'])));
    }

    public function testSignWithSecretThrowsInvalidArgumentExceptionOnInvalidKeyLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key must be ' . SODIUM_CRYPTO_AUTH_KEYBYTES . ' long.');
        $key = 'secret';
        $this->crypt->signWithSecret('Hello World', $key, false);
    }

    public function testSignWithSecretThrowsInvalidArgumentExceptionOnEmptyMessage()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data must not be empty.');
        $key = random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES);
        $this->crypt->signWithSecret('', $key, false);
    }

    public function testSignWithSecretReturnsSignatureAsHexString()
    {
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES));
        $message = 'Hello World';
        $signature = $this->crypt->signWithSecret($message, $key, true);
        $this->assertEquals(SODIUM_CRYPTO_AUTH_BYTES, strlen(hex2bin($signature)));
    }

    public function testSignWithSecretWithRawKeyReturnsSignatureAsHexString()
    {
        $key = random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES);
        $message = 'Hello World';
        $signature = $this->crypt->signWithSecret($message, $key, false);
        $this->assertEquals(SODIUM_CRYPTO_AUTH_BYTES, strlen(hex2bin($signature)));
    }

    public function testVerifyWithSecretThrowsInvalidArgumentExceptionOnInvalidKeyLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key must be ' . SODIUM_CRYPTO_AUTH_KEYBYTES . ' long.');
        $key = 'secret';
        $this->crypt->verifyWithSecret(bin2hex(random_bytes(SODIUM_CRYPTO_AUTH_BYTES)), 'A message', $key, false);
    }

    public function testVerifyWithSecretReturnsFalseOnInvalidSignature()
    {
        $key = random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES);
        $this->assertFalse(
            $this->crypt->verifyWithSecret(bin2hex(random_bytes(SODIUM_CRYPTO_AUTH_BYTES)), 'A message', $key, false)
        );
    }

    public function testVerifyWithSecretReturnsTrueOnValidSignature()
    {
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES));
        $message = 'Hello World';
        $signature = $this->crypt->signWithSecret($message, $key, true);
        $this->assertTrue($this->crypt->verifyWithSecret($signature, $message, $key, true));
    }

    public function testGenerateEncryptionSecretReturns256BitRandomKeyAsHex()
    {
        $secret = $this->crypt->generateEncryptionSecret();
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, strlen(hex2bin($secret)));
    }

    public function testGetMessageSignatureThrowsInvalidArgumentExceptionOnInvalidKeyLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' long.');
        $key = bin2hex('secret');
        $this->crypt->getMessageSignature(bin2hex('Hello World'), $key);
    }

    public function testGetMessageSignatureThrowsInvalidArgumentExceptionOnEmptyMessage()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The message must not be empty.');
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES));
        $this->crypt->getMessageSignature('', $key);
    }

    public function testGetMessageSignatureReturnsMessageSignatureAsHexString()
    {
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES));
        $message = 'Hello World';
        $signature = $this->crypt->getMessageSignature($message, $key);
        $this->assertEquals(SODIUM_CRYPTO_SIGN_BYTES, strlen(hex2bin($signature)));
    }

    public function testGenerateSigningKeypairReturnsArrayWithHexEncodedKeys()
    {
        $keypair = $this->crypt->generateSigningKeypair('secret_password');
        $this->assertEquals(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen(hex2bin($keypair['publicKey'])));
        $this->assertEquals(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, strlen(hex2bin($keypair['privateKey'])));
        $this->assertEquals(SODIUM_CRYPTO_SIGN_KEYPAIRBYTES, strlen(hex2bin($keypair['keypair'])));
    }

    public function testVerifyMessageSignatureThrowsInvalidArgumentExceptionOnInvalidKeyLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' long.');
        $key = bin2hex('secret');
        $this->crypt->verifyMessageSignature(bin2hex('Hello World'), bin2hex('signature'), $key);
    }

    public function testVerifyMessageSignatureThrowsInvalidArgumentExceptionOnInvalidSignatureLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The signature must be ' . SODIUM_CRYPTO_SIGN_BYTES . ' long.');
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_BYTES / 2));
        $this->crypt->verifyMessageSignature(bin2hex('Hello World'), bin2hex('signature'), $key);
    }

    public function testVerifyMessageSignatureThrowsInvalidArgumentExceptionOnEmptyMessage()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The message must not be empty.');
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES));
        $this->crypt->verifyMessageSignature('', bin2hex('signature'), $key);
    }

    public function testVerifyMessageSignatureReturnsTrueOnValidSignature()
    {
        $key = $this->crypt->generateSigningKeypair('secret_password');
        $message = 'Hello World';
        $signature = $this->crypt->getMessageSignature($message, $key['privateKey']);
        $this->assertTrue($this->crypt->verifyMessageSignature($message, $signature, $key['publicKey']));
    }

    public function testVerifyMessageSignatureReturnsFalseOnInvalidSignature()
    {
        $key = $this->crypt->generateSigningKeypair('secret_password');
        $message = 'Hello World';
        $signature = $this->crypt->getMessageSignature($message, $key['privateKey']);
        $this->assertFalse($this->crypt->verifyMessageSignature($message, bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_BYTES)), $key['publicKey']));
    }

    public function testVerifyMessageReturnsFalseOnIncorrectPublicKey()
    {
        $key = $this->crypt->generateSigningKeypair('secret_password');
        $message = 'Hello World';
        $signature = $this->crypt->getMessageSignature($message, $key['privateKey']);
        $this->assertFalse($this->crypt->verifyMessageSignature($message, $signature, bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES))));
    }

    public function testHashPasswordGeneratesDeterministicHash()
    {
        $password = 'secret_password';
        $hash1 = $this->crypt->hashPassword($password);
        $hash2 = $this->crypt->hashPassword('secret_password');
        $this->assertEquals("00b1d851873ca25f4fd9de309b7fc68382c0411f169675a8705bebc8f7a660f4", $hash1);
        $this->assertEquals($hash1, $hash2);
    }


    public function testGetSignedMessageThrowsInvalidArgumentExceptionOnInvalidKeyLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' long.');
        $key = bin2hex('secret');
        $this->crypt->getSignedMessage('Hello World', $key);
    }

    public function testGetSignedMessageThrowsInvalidArgumentExceptionOnEmptyMessage()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The message must not be empty.');
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES));
        $this->crypt->getSignedMessage('', $key);
    }

    public function testGetSignedMessageReturnsBase64EncodedMessageWithSignature()
    {
        $key = $this->crypt->generateSigningKeypair('secret_password');
        $message = 'Hello World';
        $signedMessage = $this->crypt->getSignedMessage($message, $key['privateKey']);
        $this->assertEquals('UPJvWHfjAK3hxdnwxlyGEBN4zaEnYLGrCwfvguZL/iF34sVspaOBXK9d8VKVpb4lczCZ17e1R37ENke5sTFYCEhlbGxvIFdvcmxk', $signedMessage);
    }

    public function testGenerateSigningSecretReturnsHexEncodedSecret()
    {
        $secret = $this->crypt->generateSigningSecret();
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, strlen(hex2bin($secret)));
    }

    public function testVerifySignedMessageThrowsInvalidArgumentExceptionOnInvalidKeyLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' long.');
        $key = bin2hex('secret');
        $this->crypt->verifySignedMessage('UPJvWHfjAK3hxdnwxlyGEBN4zaEnYLGrCwfvguZL/iF34sVspaOBXK9d8VKVpb4lczCZ17e1R37ENke5sTFYCEhlbGxvIFdvcmxk', $key);
    }

    public function testVerifySignedMessageThrowsInvalidArgumentExceptionOnEmptyMessage()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The message must not be empty.');
        $key = bin2hex(random_bytes(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES));
        $this->crypt->verifySignedMessage('', $key);
    }

    public function testVerifySignedMessageThrowsRuntimeExceptionOnInvalidSignature()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not verify message.');
        $key = $this->crypt->generateSigningKeypair('secret_password');
        $badKey = $this->crypt->generateSigningKeypair('bad_password');
        $message = 'Hello World';
        $signedMessage = $this->crypt->getSignedMessage($message, $key['privateKey']);
        $this->crypt->verifySignedMessage($signedMessage, $badKey['publicKey']);
    }

    public function testVerifySignedMessageReturnsPlainTextMessageOnValidSignature()
    {
        $key = $this->crypt->generateSigningKeypair('secret_password');
        $message = 'Hello World';
        $signedMessage = $this->crypt->getSignedMessage($message, $key['privateKey']);
        $this->assertEquals($message, $this->crypt->verifySignedMessage($signedMessage, $key['publicKey']));
    }
}
