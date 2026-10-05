package com.example.ztgw.model;

import java.time.Instant;

public class Challenge {

    public enum Purpose {
        ATTEST, ROTATE
    }

    public enum Status {
        ISSUED, CONSUMED
    }

    private final Purpose purpose;
    private final String challengeId;
    private final String nonce;
    private final String deviceId;
    private final long policyVersion;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile Status status;

    public Challenge(Purpose purpose, String challengeId, String nonce, String deviceId, long policyVersion,
                     Instant issuedAt, Instant expiresAt) {
        this.purpose = purpose;
        this.challengeId = challengeId;
        this.nonce = nonce;
        this.deviceId = deviceId;
        this.policyVersion = policyVersion;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = Status.ISSUED;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public Purpose getPurpose() {
        return purpose;
    }

    public String getNonce() {
        return nonce;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public long getPolicyVersion() {
        return policyVersion;
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

    public boolean hasExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    /** Atomic one-shot consumption; exactly one concurrent caller wins. */
    public boolean tryConsume() {
        if (status != Status.ISSUED) {
            return false;
        }
        synchronized (this) {
            if (status != Status.ISSUED) {
                return false;
            }
            status = Status.CONSUMED;
            return true;
        }
    }
}
