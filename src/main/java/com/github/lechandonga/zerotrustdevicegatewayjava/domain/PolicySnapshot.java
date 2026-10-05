package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import java.time.Instant;
import java.util.Set;

/**
 * 不可变策略快照：单调递增版本号 + 受信固件度量基线 + 吊销名单。
 * 任何一次准入判定都绑定一个确定版本，历史版本保留用于审计与证据解释。
 */
public record PolicySnapshot(long version,
                             Instant createdAt,
                             Set<String> trustedMeasurements,
                             Set<String> revokedDevices,
                             String note) {

    public boolean trustsMeasurement(String measurement) {
        return trustedMeasurements.contains(measurement);
    }

    public boolean revokes(String deviceId) {
        return revokedDevices.contains(deviceId);
    }
}
