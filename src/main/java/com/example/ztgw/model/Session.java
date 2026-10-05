package com.example.ztgw.model;

import java.time.Instant;

public class Session {

    private final String sessionToken;
    private final String deviceId;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final long policyVersion;
    private final String keyFingerprint;
    private final String measurement;
    private final String decisionId;

    public Session(String sessionToken, String deviceId, Instant issuedAt, Instant expiresAt,
                   long policyVersion, String keyFingerprint, String measurement, String decisionId) {
        this.sessionToken = sessionToken;
        this.deviceId = deviceId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.policyVersion = policyVersion;
        this.keyFingerprint = keyFingerprint;
        this.measurement = measurement;
        this.decisionId = decisionId;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public long getPolicyVersion() {
        return policyVersion;
    }

    public String getKeyFingerprint() {
        return keyFingerprint;
    }

    public String getMeasurement() {
        return measurement;
    }

    public String getDecisionId() {
        return decisionId;
    }

    public boolean hasExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
