<?php

namespace Gebler\Encryption;

use InvalidArgumentException;
use RuntimeException;
use SodiumException;
use Exception;

class Encryption
{
    public function __construct()
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('The sodium extension is not loaded.');
        }
    }

    /**
     * Generate a deterministic 32 byte hash from the given password and encode as hex.
     * Use this to obtain a text representation of the password that can be easily stored or transmitted.
     * @param string $password
     * @return string
     */
    public function hashPassword(string $password): string
    {
        try {
            return sodium_bin2hex(sodium_crypto_generichash($password, "", 32));
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not generate password hash.', 0, $e);
        }
    }

    /**
     * Symmetric encryption using a password.
     * @param string $data The data to encrypt
     * @param string $password The password to use for encryption
     * @param int $sodium_crypto_pwhash_opslimit maximum amount of computations
     * @param int $sodium_crypto_pwhash_memlimit maximum amount of RAM that the function will use, in bytes.
     * @return string The encrypted data
     * @throws RuntimeException If encryption fails
     */
    public function encryptWithPassword(string $data, string $password, $sodium_crypto_pwhash_opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, $sodium_crypto_pwhash_memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE): string
    {
        try {
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $key = sodium_crypto_pwhash(
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                $password,
                $salt,
                $sodium_crypto_pwhash_opslimit,
                $sodium_crypto_pwhash_memlimit
            );
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($data, $nonce, $key);
            $encrypted = sodium_bin2base64($salt . $nonce . $ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL);
            sodium_memzero($password);
            sodium_memzero($key);
            sodium_memzero($nonce);
            return $encrypted;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not encrypt data.', 0, $e);
        } catch (Exception $e) {
            throw new RuntimeException('Unable to generate random bytes', 0, $e);
        }
    }

    /**
     * Symmetric decryption using a password.
     * @param string $encrypted The encrypted data
     * @param string $password The password to use for decryption
     * @param int $sodium_crypto_pwhash_opslimit maximum amount of computations
     * @param int $sodium_crypto_pwhash_memlimit maximum amount of RAM that the function will use, in bytes.
     * @return string The decrypted data
     * @throws RuntimeException If decryption fails
     */
    public function decryptWithPassword(string $encrypted, string $password, $sodium_crypto_pwhash_opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,$sodium_crypto_pwhash_memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE): string
    {
        try {
            $decoded = sodium_base642bin($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL);
            $salt = mb_substr($decoded, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES, '8bit');
            $nonce = mb_substr(
                $decoded,
                SODIUM_CRYPTO_PWHASH_SALTBYTES,
                SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
                '8bit'
            );
            $ciphertext = mb_substr(
                $decoded,
                SODIUM_CRYPTO_PWHASH_SALTBYTES + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
                null,
                '8bit'
            );
            $key = sodium_crypto_pwhash(
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                $password,
                $salt,
                $sodium_crypto_pwhash_opslimit,
                $sodium_crypto_pwhash_memlimit
            );
            $decrypted = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
            if ($decrypted === false) {
                throw new RuntimeException('Could not decrypt data.');
            }
            sodium_memzero($password);
            sodium_memzero($key);
            sodium_memzero($nonce);
            return $decrypted;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not decrypt data.', 0, $e);
        }
    }

    /**
     * Symmetrical (shared secret) encryption of a message with a password.
     * @param string $data
     * @param string|null $inputKey
     * @param bool $keyIsHex
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function encryptWithSecret(string $data, ?string &$inputKey = "", bool $keyIsHex = true): string
    {
        try {
            if ($data === '') {
                throw new InvalidArgumentException('Data to encrypt cannot be empty.');
            }
            if ($inputKey === null || $inputKey === '') {
                $inputKey = sodium_bin2hex(sodium_crypto_secretbox_keygen());
                $keyIsHex = true;
            }

            $key = $inputKey;
            if ($keyIsHex) {
                $key = sodium_hex2bin($inputKey);
            }

            if (strlen($key) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                $key = sodium_crypto_generichash($key, "", 32);
            }

            if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                throw new InvalidArgumentException('Key must be 32 bytes long');
            }
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $encrypted = sodium_crypto_secretbox($data, $nonce, $key);
            $encrypted = sodium_bin2base64($nonce . $encrypted, SODIUM_BASE64_VARIANT_ORIGINAL);
            sodium_memzero($data);
            sodium_memzero($key);
            sodium_memzero($nonce);
            return $encrypted;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not encrypt data', 0, $e);
        } catch (InvalidArgumentException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new RuntimeException('Unable to generate random bytes', 0, $e);
        }
    }

    /**
     * Symmetrical (shared secret) decryption of a message with a password.
     * @param string $data
     * @param string $inputKey
     * @param bool $keyIsHex
     * @return string
     * @throws RuntimeException
     * @throws InvalidArgumentException
     */
    public function decryptWithSecret(string $data, string $inputKey, bool $keyIsHex = true): string
    {
        try {
            if ($keyIsHex) {
                $inputKey = sodium_hex2bin($inputKey);
            }
            if (strlen($inputKey) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                $inputKey = sodium_crypto_generichash($inputKey, "", 32);
            }
            if (strlen($inputKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                throw new InvalidArgumentException('Key must be 32 bytes long');
            }
            $decoded = sodium_base642bin($data, SODIUM_BASE64_VARIANT_ORIGINAL);
            if (strlen($decoded) < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
                throw new InvalidArgumentException('Encrypted data is too short');
            }
            $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
            $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
            $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $inputKey);
            if ($plaintext === false) {
                throw new InvalidArgumentException('Could not decrypt data; probably the wrong password');
            }
            sodium_memzero($ciphertext);
            sodium_memzero($nonce);
            sodium_memzero($inputKey);
            return $plaintext;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not decrypt data; probably password wrong format', 0, $e);
        }
    }

    /**
     * Symmetrical message authentication code (MAC) of a message with a password.
     * Returns a hex string of the message signature.
     */
    public function signWithSecret(string $data, ?string &$key = "", bool $keyIsHex = true): string
    {
        try {
            if ($key === null || $key === "") {
                $key = $this->generateSigningSecret();
            }

            $realKey = $key;

            if ($keyIsHex) {
                $realKey = sodium_hex2bin($key);
            }

            if (strlen($realKey) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
                throw new InvalidArgumentException('The key must be ' . SODIUM_CRYPTO_AUTH_KEYBYTES . ' long.');
            }

            if (strlen($data) === 0) {
                throw new InvalidArgumentException('The data must not be empty.');
            }

            $result = sodium_bin2hex(sodium_crypto_auth($data, $realKey));
            sodium_memzero($data);
            sodium_memzero($realKey);
            return $result;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not sign data', 0, $e);
        }
    }

    /**
     * Verifies the MAC of a message with a password.
     */
    public function verifyWithSecret(string $signature, string $data, string $key, bool $keyIsHex = true): bool
    {
        try {
            $signature = sodium_hex2bin($signature);
            if ($keyIsHex) {
                $key = sodium_hex2bin($key);
            }
            if (strlen($key) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
                throw new InvalidArgumentException('The key must be ' . SODIUM_CRYPTO_AUTH_KEYBYTES . ' long.');
            }
            $result = sodium_crypto_auth_verify($signature, $data, $key);
            sodium_memzero($signature);
            sodium_memzero($key);
            return $result;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not verify data', 0, $e);
        }
    }

    /**
     * Generates a random key for use with symmetrical signing and return as a hex string.
     * @return string
     */
    public function generateSigningSecret(): string
    {
        try {
            return sodium_bin2hex(sodium_crypto_auth_keygen());
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not generate signing key', 0, $e);
        }
    }

    /**
     * Generate a random key for use with symmetrical encryption and return as a hex string.
     */
    public function generateEncryptionSecret(): string
    {
        try {
            return sodium_bin2hex(sodium_crypto_secretbox_keygen());
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not generate encryption key', 0, $e);
        }
    }

    /**
     * Generate an X25519 key pair and return the public and private key as an array of hex strings.
     * If a password is supplied, the generated key pair will be deterministic.
     */
    public function generateEncryptionKeypair(?string $password = ''): array
    {
        try {
            $keypair = empty($password) ?
                sodium_crypto_box_keypair() :
                sodium_crypto_box_seed_keypair(sodium_crypto_generichash($password, "", 32));

            return [
                'keypair' => sodium_bin2hex($keypair),
                'publicKey' => sodium_bin2hex(sodium_crypto_box_publickey($keypair)),
                'privateKey' => sodium_bin2hex(sodium_crypto_box_secretkey($keypair)),
            ];
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not generate keypair.', 0, $e);
        }
    }

    /**
     * Generate an Ed25519 key pair and return the public and private key as an array of hex strings.
     * If a password is supplied, the generated key pair will be deterministic.
     */
    public function generateSigningKeypair(?string $password = ''): array
    {
        try {
            $keypair = empty($password) ?
                sodium_crypto_sign_keypair() :
                sodium_crypto_sign_seed_keypair(sodium_crypto_generichash($password, "", 32));

            return [
                'keypair' => sodium_bin2hex($keypair),
                'publicKey' => sodium_bin2hex(sodium_crypto_sign_publickey($keypair)),
                'privateKey' => sodium_bin2hex(sodium_crypto_sign_secretkey($keypair)),
            ];
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not generate keypair.', 0, $e);
        }
    }

    /**
     * Sign a message with an Ed25519 private key and return the signed message.
     */
    public function getSignedMessage(string $message, string $privateKey): string
    {
        try {
            $privateKey = sodium_hex2bin($privateKey);
            if (strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                throw new InvalidArgumentException('The key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' long.');
            }

            if (strlen($message) === 0) {
                throw new InvalidArgumentException('The message must not be empty.');
            }

            return sodium_bin2base64(sodium_crypto_sign($message, $privateKey), SODIUM_BASE64_VARIANT_ORIGINAL);
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not sign data', 0, $e);
        }
    }

    /**
     * Verify a signed message with an Ed25519 public key, ensuring it hasn't been tampered with and return the message.
     */
    public function verifySignedMessage(string $signedMessage, string $publicKey): string
    {
        try {
            $publicKey = sodium_hex2bin($publicKey);
            $signedMessage = sodium_base642bin($signedMessage, SODIUM_BASE64_VARIANT_ORIGINAL);
            if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new InvalidArgumentException('The key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' long.');
            }

            if (strlen($signedMessage) === 0) {
                throw new InvalidArgumentException('The message must not be empty.');
            }

            $result = sodium_crypto_sign_open($signedMessage, $publicKey);
            if ($result === false) {
                throw new RuntimeException('Could not verify message.');
            }
            return $result;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not verify data', 0, $e);
        }
    }

    /**
     * Sign a message with an ED25519 private key and return the signature.
     */
    public function getMessageSignature(string $message, string $privateKey): string
    {
        try {
            $privateKey = sodium_hex2bin($privateKey);
            if (strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                throw new InvalidArgumentException('The key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' long.');
            }

            if (strlen($message) === 0) {
                throw new InvalidArgumentException('The message must not be empty.');
            }

            return sodium_bin2hex(sodium_crypto_sign_detached($message, $privateKey));
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not sign data', 0, $e);
        }
    }

    /**
     * Verify a signed message with an ED25519 public key, ensuring it hasn't been tampered with and return true
     * if the signature is valid.
     */
    public function verifyMessageSignature(string $message, string $signature, string $publicKey): bool
    {
        try {
            $publicKey = sodium_hex2bin($publicKey);
            $signature = sodium_hex2bin($signature);
            if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new InvalidArgumentException('The key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' long.');
            }

            if (strlen($message) === 0) {
                throw new InvalidArgumentException('The message must not be empty.');
            }

            if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
                throw new InvalidArgumentException('The signature must be ' . SODIUM_CRYPTO_SIGN_BYTES . ' long.');
            }

            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not verify data', 0, $e);
        }
    }

    /**
     * Encrypt a message with the recipient public key and optionally sign with the sender private key.
     * @param string $data
     * @param string $recipientPublicKey
     * @param string|null $senderPrivateKey
     * @return string
     */
    public function encryptWithKey(string $data, string $recipientPublicKey, ?string $senderPrivateKey = null): string
    {
        try {
            if ($senderPrivateKey !== null) {
                return $this->encryptAuthenticated($data, $recipientPublicKey, $senderPrivateKey);
            }
            // Anonymous encryption
            $recipientPublicKey = sodium_hex2bin($recipientPublicKey);
            $encrypted = sodium_crypto_box_seal($data, $recipientPublicKey);
            sodium_memzero($recipientPublicKey);
            sodium_memzero($data);
            return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL);
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not encrypt data', 0, $e);
        } catch (Exception $e) {
            throw new RuntimeException('Unable to generate random bytes', 0, $e);
        }
    }

    /**
     * Decrypt a message with either the recipient keypair for anonymous decryption, or
     * the recipient private key and sender public key for authenticated decryption.
     */
    public function decryptWithKey(string $data, string $recipientKey, ?string $senderPublicKey = null): string
    {
        try {
            if ($senderPublicKey !== null) {
                return $this->decryptAuthenticated($data, $recipientKey, $senderPublicKey);
            }
            // Anonymous decryption
            $recipientKeyPair = sodium_hex2bin($recipientKey);
            $decoded = sodium_base642bin($data, SODIUM_BASE64_VARIANT_ORIGINAL);
            $plaintext = sodium_crypto_box_seal_open($decoded, $recipientKeyPair);
            sodium_memzero($recipientKeyPair);
            sodium_memzero($decoded);
            sodium_memzero($data);
            return $plaintext;
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not decrypt data', 0, $e);
        }
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    private function encryptAuthenticated(string $data, string $recipientPublicKey, string $senderPrivateKey): string
    {
        $senderPrivateKey = sodium_hex2bin($senderPrivateKey);
        $recipientPublicKey = sodium_hex2bin($recipientPublicKey);

        $key = sodium_crypto_box_keypair_from_secretkey_and_publickey($senderPrivateKey, $recipientPublicKey);

        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $ciphertext = sodium_crypto_box($data, $nonce, $key);

        sodium_memzero($data);
        sodium_memzero($key);

        return sodium_bin2base64($nonce . $ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    /**
     * @throws SodiumException
     */
    private function decryptAuthenticated(string $data, string $recipientPrivateKey, string $senderPublicKey): string
    {
        $senderPublicKey = sodium_hex2bin($senderPublicKey);
        $recipientPrivateKey = sodium_hex2bin($recipientPrivateKey);

        $key = sodium_crypto_box_keypair_from_secretkey_and_publickey($recipientPrivateKey, $senderPublicKey);

        $data = sodium_base642bin($data, SODIUM_BASE64_VARIANT_ORIGINAL);

        $nonce = substr($data, 0, SODIUM_CRYPTO_BOX_NONCEBYTES);
        $ciphertext = substr($data, SODIUM_CRYPTO_BOX_NONCEBYTES);

        $plaintext = sodium_crypto_box_open($ciphertext, $nonce, $key);

        sodium_memzero($data);
        sodium_memzero($key);

        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed.');
        }
        return $plaintext;
    }
}
