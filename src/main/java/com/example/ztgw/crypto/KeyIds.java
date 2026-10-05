package com.example.ztgw.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;

public final class KeyIds {

    private KeyIds() {
    }

    public static String fingerprint(PublicKey publicKey) {
        return fingerprint(publicKey.getEncoded());
    }

    public static String fingerprint(byte[] der) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(der));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String fingerprintB64(String x509Base64) {
        return fingerprint(Base64.getDecoder().decode(x509Base64));
    }

    public static String canonicalHash(String payload) {
        return fingerprint(payload.getBytes(StandardCharsets.UTF_8));
    }
}
