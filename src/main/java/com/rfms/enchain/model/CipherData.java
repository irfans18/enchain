package com.rfms.enchain.model;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.rfms.enchain.service.Stringify;
import com.rfms.enchain.util.Mapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;
import java.util.List;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CipherData implements Stringify<CipherData> {
    private String voterId;
    private List<State> states;
    private Integer index;
    private Timestamp createdAt;
    @Override
    public String toJSON() {
        try {
            return Mapper.mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CipherData fromJSON(String payload) {
        try {
            return Mapper.mapper.readValue(payload, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }


}