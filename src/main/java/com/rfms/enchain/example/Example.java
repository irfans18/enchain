package com.rfms.enchain.example;

import com.rfms.enchain.service.Crypto;

public class Example {
    public static void main(String[] args) {
        Crypto crypto = new Crypto();
        System.out.println(crypto.getDigest("rabbit4"));
    }
}
