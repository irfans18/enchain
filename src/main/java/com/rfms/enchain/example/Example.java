package com.rfms.enchain.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.rfms.enchain.Enchain;
import com.rfms.enchain.model.BlockRequest;
import com.rfms.enchain.model.Blockchain;
import com.rfms.enchain.model.CipherData;
import com.rfms.enchain.model.State;
import com.rfms.enchain.service.Crypto;
import com.rfms.enchain.util.Mapper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

public class Example {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Crypto crypto = new Crypto().generateKeyPair();
        System.out.println(crypto.getDigest("fullhd"));
        createBlockExample(crypto);
        cryptoExample(crypto);
    }

    private static void createBlockExample(Crypto crypto){
        Enchain enchain = new Enchain(crypto);
        BlockRequest br = BlockRequest.builder()
                .prevHash("790a0ec7-bc5a-469a-8667-cb792f88f44d")
                .cipherData(
                        CipherData.builder()
                                .states(List.of(
                                        State.builder()
                                                .candidateId("f8a03e87-3474-4d4b-8459-df303178580a")
                                                .count(10)
                                                .build(),
                                        State.builder()
                                                .candidateId("b04670de-ca9e-4405-85cd-5bf24ec9b907")
                                                .count(100)
                                                .build()
                                ))
                                .voterId("2446989c-9462-4f92-a992-15c20d682f74")
                                .index(7)
                                .createdAt(Timestamp.from(Instant.now()))
                                .build()
                )
                .build();
        Blockchain block = enchain.createBlock(br);
        System.out.println(block.toJSON());
        System.out.println(block.getPrevHash());
        System.out.println(block.getCipherText());
        System.out.println(block.getVoter());
        System.out.println(block.getIndex());
    }
    private static void cryptoExample(Crypto crypto){
        try {
            String encrypted =
                    "RPkpQdCDvKcWlBWXHAm5CbLtHIaMEiHvXo/GK4x+/5NqpsIhDE3sRJevNtU2vdkEA5HMUVcKUA4lJHTEIuhGPkW6c+hTPFkKHTp2UpzRh9lQ58/eRyjYmy+SJSmuedjPLeCP6fWVjyn2qf//zwJODRr9b7RkmdejYSfzveEVhUZ0Z5Tr/ONJkqfdeht/UY1sprswBJtA5XDgYuydsxA8XYb1t5rvWMdhmclvzr2JN6+5RbC+BHZzrFzZAhql30lMoQOYvLQBFHeBDwXCdAwLt2k82xSMr8v65FMoygkdEM3P4yQjxtR6uQXFNZ1WfUHZDwVcCF6gfpTXMyWRv70jBA==".replace("\n","").replace("\\n", "");
            // crypto.generateKeyPair();
            // RSAPublicKey publicKey = crypto.getPublicKey();
            // String pem = crypto.convertToPem(publicKey);
            // String encrypted = crypto.encrypt("free kick", crypto.pubKeyFromPem(pem));
            // System.out.println(encrypted);

            RSAPrivateKey privateKey = crypto.getPrivateKey();
            // String privpem = crypto.convertToPem(privateKey);
            String privpem =
                    "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyjj6BPQqW2ktx\n" +
                    "6WHLY9XKjKEvf6paOOT9aSPOQtyErQqUt7M1e76/GQa+xy2Suda7UgtIxW1CIK2X\n" +
                    "6G/Yxjg+RNdZQVYE33FA19IIO9HXOwE476wr42tQrqb4fwD85L8k3dXiLAyv2kH/\n" +
                    "a9z8sjEMvGrwh8oxv6w6lVivlgXDRSjSuYExPqq/wPvuP+w/dYjHBJ3c1nAvs3s2\n" +
                    "P+OFgRwr7R8CcTxETY7Mbm9+P+V2WjhZgRGyEv0pB8iNGbUKqtkg6Ys9lKkRqRJY\n" +
                    "Xt28DLSiHQciw1oOEjnhA/cHcrfJLkR590dOEx/dmW74MPQ3vbYUu0r2vbGuh5fC\n" +
                    "ZUq26o3BAgMBAAECggEANbyYdBW2V6MX3I7z1x3TLDO5mM1vq9p+lANt+rflnOpl\n" +
                    "Ck/k175HsERsYsMX5JYYWWS+L6b3FFU4WUTjUFaLe7YFJ4ABztKeR3kMZVz3cLJ5\n" +
                    "0jRTWRwG4o/FgXjbh8CiBArdQUWnhc8GWMQSDFzmZSJZfs0nHWTFhRYITEO2tUbc\n" +
                    "fxA/LcV5UkdgOh0AV5nH8k/89vhgMnzxu9A6CBqx+V/7t7D2VPejdri/2KdNdDbz\n" +
                    "GQeKTaOCTVSyULQqDo+Pfu4cfjNZtdWVK1zvqUY+pku11br5HwORlUi3iw0orYda\n" +
                    "TmUDwxuGiJiGEtYw8tFPimh0r/4pqhyd/TEaXkDR7wKBgQDFJBeYxDuCBbHfkoxt\n" +
                    "Zph9P/5d1+hiztoPTk/z8/qQYYroWAmJ4qqLblNNDp/h/F96oXWm/Eb3Mxk7xCR4\n" +
                    "uPFtSq+yTD0dnNTmGABaypzeTBt2Vcmivd442WxCJpJnFaVwIpB9M+KvaZd2+xNh\n" +
                    "WOMVtrnetXWV8qUhx5poR5a+7wKBgQDn3aJkOTdFNPccmTUvyBKs60jypJKVftfL\n" +
                    "08SI2fKp7YumMhpQJbyuTwO+o2yPyl5un1sc3r/hvLSbmjF7mPrbOfwL/KEvTMiO\n" +
                    "Y8NDm3FbWUdcYkzHqTuvxG01Jpe5iKgRDley5mQaI2eVIfRITApJ7YNGQiPoGSAR\n" +
                    "A9uCqVR+TwKBgQCMfJbwP88kbkh+yaGXCMjcYPE1EPrDByOwSp+BerlxkIF759kM\n" +
                    "UOI2MK3eOPDJC59C9bKxCBDOcrSlubY/7ZPmzZV9WwUmiC/TtQDzsnWtmNDtOF9T\n" +
                    "wTiOjKqwTWqBWZSm34rWHlaJqJbOrEf4VG6nd6rnQasE64CwHN01OOb9MwKBgGLR\n" +
                    "b7NdOzQQpbyXgzZxA5yUzkszXpG+NIRXJazZjnVjmx/ivJop6ycy37qw9cS2j9Z/\n" +
                    "rho4yPiRLzwd1DcD9O3X4ZbOPXfmNpeQ5xh6OC6hdytlbamuc5Sul4iOgR1+o3pZ\n" +
                    "bYD+de0555yEkxL47W2if09DQwBZLPRze2tNdYg7AoGAbxQGGLarCaVooiZthjpR\n" +
                    "1DBa9fvkWh3riaGO5l143gzezxPNSI4YvQVYelHVs+FjUvcxhKWqZSJk8Fu5lw8s\n" +
                    "iXcW7DNEV3MyCVrOij/d4rEqW0figD3JqMLV+W5ZuZNPK1bLIpKdx+rzUjwANosE\n" +
                    "VFCywf5MEpldj6mzs02+S0k=\n" +
                    "\n" +
                    "-----END RSA PRIVATE KEY-----";
            String decrypted = crypto.decrypt(encrypted, crypto.privKeyFromPem(privpem));
            System.out.println(decrypted);
            List<State> states =Mapper.mapper.readValue(decrypted, new TypeReference<>() {
            });
            for (State state : states) {
                System.out.println(state.getCandidateId());
                System.out.println(state.getCount());
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeySpecException | JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
