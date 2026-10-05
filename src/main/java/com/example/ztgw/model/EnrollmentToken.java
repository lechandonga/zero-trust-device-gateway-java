package com.example.ztgw.model;

import java.time.Instant;

public class EnrollmentToken {

    public enum Status {
        ISSUED, CONSUMED
    }

    private final String token;
    private final String boundDeviceId;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile Status status;
    private volatile Instant consumedAt;
    private volatile String consumedByDevice;

    public EnrollmentToken(String token, String boundDeviceId, Instant issuedAt, Instant expiresAt) {
        this.token = token;
        this.boundDeviceId = boundDeviceId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = Status.ISSUED;
    }

    public String getToken() {
        return token;
    }

    public String getBoundDeviceId() {
        return boundDeviceId;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public String getConsumedByDevice() {
        return consumedByDevice;
    }

    public boolean hasExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public boolean consume(String deviceId) {
        if (status != Status.ISSUED) {
            return false;
        }
        synchronized (this) {
            if (status != Status.ISSUED) {
                return false;
            }
            status = Status.CONSUMED;
            consumedAt = Instant.now();
            consumedByDevice = deviceId;
            return true;
        }
    }
}
