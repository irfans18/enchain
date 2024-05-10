package com.rfms.enchain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rfms.enchain.model.BlockRequest;
import com.rfms.enchain.model.Blockchain;
import com.rfms.enchain.service.Crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Enchain {
    private final Crypto cryptoService;

    public Enchain(Crypto cryptoService) {
        this.cryptoService = cryptoService;
    }

    public Blockchain createBlock(BlockRequest b) {
        ObjectMapper mapper = new ObjectMapper();

        String encrypted;
        try {
            encrypted = cryptoService.encrypt(mapper.writeValueAsString(b.getCipherData()));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        String hashData = cryptoService.getDiggest(b.getPrevHash() + encrypted);

        try {
            cryptoService.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return Blockchain.builder()
                .votersId(b.getCipherData().getVoterId())
                .prevHash(b.getPrevHash())
                .hashData(hashData)
                .cipherText(encrypted)
                .index(b.getCipherData().getIndex())
                .build();
    }
}
