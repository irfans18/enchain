package com.rfms.enchain.model;


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
public class CipherData {
    private String voterId;
    private List<State> states;
    private Integer index;
    private Timestamp createdAt;

}