package com.rfms.enchain.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public interface Stringify<T> {
    String toJSON();
    T fromJSON(String payload);
}
