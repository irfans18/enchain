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
public class Blockchain implements Stringify<Blockchain> {
    private String prevHash;
    private String cipherText;
    private Integer index;
    private String voter;
    private String hash;

    @Override
    public String toJSON() {
        try {
            return Mapper.mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Blockchain fromJSON(String payload) {
        try {
            return Mapper.mapper.readValue(payload, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }


}
