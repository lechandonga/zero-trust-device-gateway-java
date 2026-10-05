package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import java.time.Instant;

/**
 * 一次性入网令牌。expectedDeviceId 为 null 时不绑定设备；
 * 成功登记后写入 consumedAt/consumedBy，且不可逆。
 */
public final class EnrollmentToken {

    private final String value;
    private final String expectedDeviceId;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile Instant consumedAt;
    private volatile String consumedBy;

    public EnrollmentToken(String value, String expectedDeviceId, Instant issuedAt, Instant expiresAt) {
        this.value = value;
        this.expectedDeviceId = expectedDeviceId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String value() { return value; }
    public String expectedDeviceId() { return expectedDeviceId; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public Instant consumedAt() { return consumedAt; }
    public String consumedBy() { return consumedBy; }

    public boolean consumed() {
        return consumedAt != null;
    }

    public boolean expired(Instant now) {
        return now.isAfter(expiresAt);
    }

    /** 标记为已消费；只有在未消费时成功，保证只被消费一次。 */
    public synchronized boolean markConsumed(Instant at, String deviceId) {
        if (consumedAt != null) {
            return false;
        }
        this.consumedAt = at;
        this.consumedBy = deviceId;
        return true;
    }
}
