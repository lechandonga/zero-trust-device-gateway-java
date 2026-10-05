package com.github.lechandonga.zerotrustdevicegatewayjava.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 密钥标识 = SHA-256(SPKI 公钥编码) 的十六进制，可确定性地引用某一把公钥。
 */
public final class KeyIds {

    private KeyIds() {
    }

    public static String of(byte[] spki) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(spki);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String ofPayload(String payload) {
        return of(payload.getBytes(StandardCharsets.UTF_8));
    }
}
