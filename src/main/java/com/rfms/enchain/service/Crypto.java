package com.rfms.enchain.service;

import lombok.Getter;
import lombok.Setter;

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
    @Getter
    @Setter
    private RSAPrivateKey privateKey;
    @Getter
    @Setter
    private RSAPublicKey publicKey;

    /**
     * Generates an RSA key pair using the specified key size (2048 bits in this
     * implementation). The generated key pair is stored in the instance fields
     * {@link #privateKey} and {@link #publicKey}.
     *
     * @return this instance, for chaining method calls
     * @throws NoSuchAlgorithmException if the specified key size is not supported
     */
    public Crypto generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        publicKey = (RSAPublicKey) pair.getPublic();
        return this;
    }

    /**
     * Computes the SHA-256 digest of the given payload.
     * <p>
     * This method uses the {@link MessageDigest} API to compute the
     * SHA-256 digest of the given payload. The resulting digest is returned
     * as a hexadecimal string.
     * <p>
     * The payload is first encoded as UTF-8, and then the digest is
     * computed on the resulting byte array.
     * <p>
     * This method throws a {@link RuntimeException} if the SHA-256
     * algorithm is not available.
     *
     * @param payload the payload to be digested
     * @return the hexadecimal string representation of the SHA-256 digest
     */
    public String getDigest(String payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Split the given data into chunks of a specified size, separated by newline characters.
     * <p>
     * This method takes a key (such as an RSA public key) as input and splits its encoded bytes
     * into chunks of a specified size. The chunks are separated by newline characters.
     * <p>
     * This method is useful when generating a public key in PEM format, as it
     * makes it easier to read and parse the key.
     * <p>
     * @param key the key to be split
     * @param chunk_split the size of each chunk
     * @return a string containing the chunks, separated by newline characters
     */
    public String chunkSplit(Key key, Integer chunk_split) {
        return chunkSplit(Base64.getEncoder().encodeToString(key.getEncoded()), chunk_split);
    }

    /**
     * Split the given data into chunks of a specified size, separated by newline characters.
     * <p>
     * This method takes a string as input and splits its bytes into chunks of a specified size.
     * The chunks are separated by newline characters.
     * <p>
     * @param data the data to be split
     * @param chunk_split the size of each chunk
     * @return a string containing the chunks, separated by newline characters
     */
    public String chunkSplit(String data, Integer chunk_split) {
        int length = data.length();
        StringBuilder builder = new StringBuilder();

        int iteration = (length / chunk_split) + 1;
        for (int i = 0; i <= iteration; i++) {
            int begin = i * chunk_split;
            if(begin > length) break;
            int end = Math.min(length, begin + chunk_split);
            builder.append(data, begin, end);
            if (i != iteration) builder.append("\n");
        }
        return builder.toString();
    }

    /**
     * Encrypts the given payload using the private key of this instance, and splits the
     * resulting ciphertext into chunks of a specified size, separated by newline
     * characters.
     * <p>
     * This method encrypts the given payload using the private key of this instance, using
     * the RSA algorithm. The resulting ciphertext is then split into chunks of a
     * specified size, separated by newline characters.
     * <p>
     * The payload is first encoded as UTF-8, and then encrypted with the private key.
     * The resulting ciphertext is then split into chunks of a specified size, using the
     * {@link #chunkSplit} method.
     * <p>
     * This method throws a {@link RuntimeException} if the RSA algorithm is not available.
     * <p>
     * @param payload the payload to be encrypted
     * @return a string containing the chunks of the encrypted payload, separated by newline
     *         characters
     * @throws NoSuchPaddingException if the RSA algorithm is not available
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeyException if the private key is invalid
     * @throws IllegalBlockSizeException if the ciphertext is not valid
     * @throws BadPaddingException if the ciphertext is not valid
     */
    public String encrypt(String payload) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] secretMessageBytes = payload.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        String cipherText = Base64.getEncoder().encodeToString(encryptedMessageBytes);
        return chunkSplit(cipherText, 64);
    }

    /**
     * Encrypts the given payload using the private key of this instance, and splits the
     * resulting ciphertext into chunks of a specified size, separated by newline
     * characters.
     * <p>
     * This method encrypts the given payload using the private key of this instance, using
     * the RSA algorithm. The resulting ciphertext is then split into chunks of a
     * specified size, separated by newline characters.
     * <p>
     * The payload is first encoded as UTF-8, and then encrypted with the private key.
     * The resulting ciphertext is then split into chunks of a specified size, using the
     * {@link #chunkSplit} method.
     * <p>
     * This method throws a {@link RuntimeException} if the RSA algorithm is not available.
     * <p>
     * @param payload the payload to be encrypted
     * @param key used to encrypt the payload
     * @return a string containing the chunks of the encrypted payload, separated by newline
     *         characters
     * @throws NoSuchPaddingException if the RSA algorithm is not available
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeyException if the private key is invalid
     * @throws IllegalBlockSizeException if the ciphertext is not valid
     * @throws BadPaddingException if the ciphertext is not valid
     */
    public String encrypt(String payload, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] secretMessageBytes = payload.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        String cipherText = Base64.getEncoder().encodeToString(encryptedMessageBytes);
        System.out.println(cipherText);
        return chunkSplit(cipherText, 64);
    }

    /**
     * Decrypts the given ciphertext using the given key, and returns the resulting plaintext.
     * <p>
     * This method decrypts the given ciphertext using the given key, using the RSA algorithm.
     * The resulting plaintext is returned as a string.
     * <p>
     * The ciphertext is first decoded from Base64, and then decrypted with the given key.
     * The resulting decrypted bytes are then converted to a string using the UTF-8 character set.
     * <p>
     * This method throws a {@link NoSuchPaddingException} if the RSA algorithm is not available,
     * a {@link NoSuchAlgorithmException} if the RSA algorithm is not available, a
     * {@link InvalidKeyException} if the public key is invalid, a
     * {@link IllegalBlockSizeException} if the ciphertext is not valid, or a
     * {@link BadPaddingException} if the ciphertext is not valid.
     * <p>
     * @param cipherText the ciphertext to be decrypted
     * @return the resulting plaintext
     */
    public String decrypt(String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] bytes = Base64.getDecoder().decode(cipherText);
        byte[] decryptedFileBytes = decryptCipher.doFinal(bytes);
        return new String(decryptedFileBytes);
    }

    
    /**
     * Decrypts the given ciphertext using the given key, and returns the resulting plaintext.
     * <p>
     * This method decrypts the given ciphertext using the given key, using the RSA algorithm.
     * The resulting plaintext is returned as a string.
     * <p>
     * The ciphertext is first decoded from Base64, and then decrypted with the given key.
     * The resulting decrypted bytes are then converted to a string using the UTF-8 character set.
     * <p>
     * This method throws a {@link NoSuchPaddingException} if the RSA algorithm is not available,
     * a {@link NoSuchAlgorithmException} if the RSA algorithm is not available, a
     * {@link InvalidKeyException} if the public key is invalid, a
     * {@link IllegalBlockSizeException} if the ciphertext is not valid, or a
     * {@link BadPaddingException} if the ciphertext is not valid.
     * <p>
     * @param cipherText the ciphertext to be decrypted
     * @param key the used for decrypt
     * @return the resulting plaintext
     */
    public String decrypt(String cipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        String clean = cipherText.replaceAll("\n","");
        System.out.println(clean);

        byte[] bytes = Base64.getDecoder().decode(clean);
        byte[] decryptedFileBytes = decryptCipher.doFinal(bytes);
        return new String(decryptedFileBytes);
    }

    /**
     * Converts a given key to PEM format.
     * <p>
     * This method takes a given key (such as an RSA private or public key) as input, and
     * converts it to PEM format. The PEM format is a text format that is commonly
     * used for storing cryptographic keys.
     * <p>
     * The resulting PEM key is returned as a string.
     * <p>
     * The method takes into account the type of the given key, and wraps it in the appropriate
     * PEM header. For example, a private key is wrapped in a "RSA PRIVATE KEY" header, while
     * a public key is wrapped in a "PUBLIC KEY" header.
     * <p>
     * This method throws an {@link IllegalArgumentException} if the given key is not an instance
     * of {@link PrivateKey} or {@link PublicKey}.
     * 
     * @param key the key to be converted
     * @return the PEM representation of the given key
     */
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


    
    /**
     * Converts a given private key in PEM format to an RSA private key object.
     * <p>
     * This method takes a given PEM-formatted private key as input, and converts it
     * to an {@link RSAPrivateKey} object.
     * <p>
     * The resulting private key is returned as an instance of {@link RSAPrivateKey}.
     * <p>
     * This method throws an {@link NoSuchAlgorithmException} if the specified key size is
     * not supported, or an {@link InvalidKeySpecException} if the given PEM key is
     * not a valid private key.
     * 
     * @param pkey the PEM-formatted private key to be converted
     * @return the RSA private key object
     * @throws NoSuchAlgorithmException if the specified key size is not supported
     * @throws InvalidKeySpecException if the given PEM key is not a valid private key
     */
    public RSAPrivateKey privKeyFromPem(String pkey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = pkey.replace("-----BEGIN RSA PRIVATE KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END RSA PRIVATE KEY-----", "");
        
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }


    /**
     * Converts a given public key in PEM format to an RSA public key object.
     * <p>
     * This method takes a given PEM-formatted public key as input, and converts it
     * to an {@link RSAPublicKey} object.
     * <p>
     * The resulting public key is returned as an instance of {@link RSAPublicKey}.
     * <p>
     * This method throws an {@link NoSuchAlgorithmException} if the specified key size is
     * not supported, or an {@link InvalidKeySpecException} if the given PEM key is
     * not a valid public key.
     * 
     * @param pubKey the PEM-formatted public key to be converted
     * @return the RSA public key object
     * @throws NoSuchAlgorithmException if the specified key size is not supported
     * @throws InvalidKeySpecException if the given PEM key is not a valid public key
     */
    public RSAPublicKey pubKeyFromPem(String pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = pubKey.replace("-----BEGIN PUBLIC KEY-----", "").replace("\n", "").replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

}

