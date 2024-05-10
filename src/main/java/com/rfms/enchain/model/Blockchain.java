package com.rfms.enchain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Blockchain {
    private String prevHash;
    private String cipherText;
    private String hashData;
    private Integer index;
    private String votersId;

}
