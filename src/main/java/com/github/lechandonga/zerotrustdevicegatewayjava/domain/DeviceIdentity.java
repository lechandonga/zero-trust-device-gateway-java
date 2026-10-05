package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import java.time.Instant;

/**
 * 设备身份：当前公钥 + 轮换过渡期保留的上一版公钥与宽限截止时间。
 * 身份对象不可变，轮换时整体替换，保证并发读取看到一致视图。
 */
public record DeviceIdentity(
        String deviceId,
        StoredKey active,
        StoredKey previous,
        Instant graceUntil,
        Instant rotatedAt,
        Instant enrolledAt) {

    public static DeviceIdentity firstEnrollment(String deviceId, StoredKey key, Instant now) {
        return new DeviceIdentity(deviceId, key, null, null, null, now);
    }

    public DeviceIdentity rotated(StoredKey newActive, Instant now, Instant graceUntil) {
        return new DeviceIdentity(deviceId, newActive, active, graceUntil, now, enrolledAt);
    }

    /** 宽限期结束 / 提前固化后丢弃旧密钥。 */
    public DeviceIdentity withoutPrevious() {
        return new DeviceIdentity(deviceId, active, null, null, rotatedAt, enrolledAt);
    }

    public boolean previousUsable(Instant now) {
        return previous != null && graceUntil != null && !now.isAfter(graceUntil);
    }
}
