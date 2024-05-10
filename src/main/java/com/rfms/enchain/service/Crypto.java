package com.rfms.enchain.service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Crypto {
    private KeyPair pair;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public Crypto generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        publicKey = (RSAPublicKey) pair.getPublic();
        return this;
    }

    public String getDiggest(String payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = md.digest(payload.getBytes(StandardCharsets.UTF_8));
            byte[] bytes = Base64.getEncoder().encode(encodedHash);

            return new String(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String chunkSplit(Key key, Integer chunk_split) {
        return chunkSplit(Base64.getEncoder().encodeToString(key.getEncoded()), chunk_split);
    }

    public String chunkSplit(String data, Integer chunk_split) {
        int length = data.length();
        StringBuilder builder = new StringBuilder();

        int iteration = length / chunk_split;
        for (int i = 0; i <= iteration; i++) {
            int begin = i * chunk_split;
            int end = Math.min(length, begin + chunk_split);
            builder.append(data, begin, end);
            if (i != iteration) builder.append("\n");
        }
        return builder.toString();
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public String encrypt(String payload) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] secretMessageBytes = payload.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        String cipherText = Base64.getEncoder().encodeToString(encryptedMessageBytes);
        return chunkSplit(cipherText, 64);
    }

    public String encrypt(String payload, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] secretMessageBytes = payload.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        String cipherText = Base64.getEncoder().encodeToString(encryptedMessageBytes);
        return chunkSplit(cipherText, 64);
    }

    public String decrypt(String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] bytes = Base64.getDecoder().decode(cipherText);
        byte[] decryptedFileBytes = decryptCipher.doFinal(bytes);
        return new String(decryptedFileBytes);
    }

    public String decrypt(String cipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, key);

        byte[] bytes = Base64.getDecoder().decode(cipherText);
        byte[] decryptedFileBytes = decryptCipher.doFinal(bytes);
        return new String(decryptedFileBytes);
    }

    public String convertToPem(Key key) {
        String type;
        String encodedKey = chunkSplit(key, 64);

        if (key instanceof PrivateKey) {
            type = "RSA PRIVATE KEY";
        } else if (key instanceof PublicKey) {
            type = "PUBLIC KEY";
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }

        return "-----BEGIN " + type + "-----\n" +
                encodedKey + "\n" +
                "-----END " + type + "-----";
    }


    public RSAPrivateKey privKeyFromPem(String pkey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = pkey.replace("-----BEGIN RSA PRIVATE KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    public RSAPublicKey pubKeyFromPem(String pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = pubKey.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}

