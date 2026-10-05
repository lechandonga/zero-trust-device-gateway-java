package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import java.security.SecureRandom;

final class Ids {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Ids() {
    }

    static String hex(int bytes) {
        byte[] data = new byte[bytes];
        RANDOM.nextBytes(data);
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            out[i * 2] = HEX[(data[i] >> 4) & 0x0F];
            out[i * 2 + 1] = HEX[data[i] & 0x0F];
        }
        return new String(out);
    }
}
