package com.github.lechandonga.zerotrustdevicegatewayjava.device;

import java.nio.charset.StandardCharsets;

/**
 * 网关与设备之间统一的签名负载构造规则（双端一致）。
 * 字段以竖线分隔，挑战 nonce 纳入签名以保证一次性、防重放。
 */
public final class SigningPayloads {

    public static final String ATTESTATION = "ATTEST";
    public static final String ROTATION = "ROTATE";

    private SigningPayloads() {
    }

    /** 证明负载：ATTEST|deviceId|nonce|measurement */
    public static byte[] attestation(String deviceId, String nonce, String measurement) {
        return (ATTESTATION + "|" + deviceId + "|" + nonce + "|" + measurement)
                .getBytes(StandardCharsets.UTF_8);
    }

    /** 轮换负载：ROTATE|deviceId|nonce|newKeyId（旧私钥签名，授权替换公钥）。 */
    public static byte[] rotation(String deviceId, String nonce, String newKeyId) {
        return (ROTATION + "|" + deviceId + "|" + nonce + "|" + newKeyId)
                .getBytes(StandardCharsets.UTF_8);
    }
}
