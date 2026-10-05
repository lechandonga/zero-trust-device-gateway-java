package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyMaterial;

import java.time.Instant;

/**
 * 设备登记在案的一把公钥。
 */
public record StoredKey(KeyMaterial material, Instant registeredAt) {

    public String keyId() {
        return material.keyId();
    }
}
