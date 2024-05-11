package com.rfms.enchain.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.rfms.enchain.service.Stringify;
import com.rfms.enchain.util.Mapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BlockRequest implements Stringify<BlockRequest> {
    private String prevHash;
    private CipherData cipherData;
    @Override
    public String toJSON() {
        try {
            return Mapper.mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public BlockRequest fromJSON(String payload) {
        try {
            return Mapper.mapper.readValue(payload, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}