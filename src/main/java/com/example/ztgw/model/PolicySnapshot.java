package com.example.ztgw.model;

import java.time.Instant;
import java.util.Set;

/**
 * Immutable, append-only rule version. Every admission decision records which
 * snapshot it was evaluated against, so conclusions stay explainable after
 * later policy changes.
 */
public record PolicySnapshot(long version,
                             Set<String> trustedMeasurements,
                             Set<String> revokedDevices,
                             Instant createdAt,
                             String reason) {

    public boolean isTrustedMeasurement(String measurement) {
        return trustedMeasurements.contains(measurement);
    }

    public boolean isRevoked(String deviceId) {
        return revokedDevices.contains(deviceId);
    }
}
