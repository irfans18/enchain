package com.rfms.enchain.example;

import com.rfms.enchain.service.Crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

public class Example {
    public static void main(String[] args) {
        Crypto crypto = new Crypto();
        System.out.println(crypto.getDigest("fullhd"));

        try {
            crypto.generateKeyPair();
            RSAPublicKey publicKey = crypto.getPublicKey();
            String pem = crypto.convertToPem(publicKey);
            String encrypted = crypto.encrypt("free kick", crypto.pubKeyFromPem(pem));
            System.out.println(encrypted);

            String decrypted = crypto.decrypt(encrypted, crypto.getPrivateKey());
            System.out.println(decrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
