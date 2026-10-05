package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import java.time.Instant;

/**
 * 一次性、有时效的证明挑战。发放时钉住当时的策略版本。
 */
public final class Challenge {

    private final String challengeId;
    private final String deviceId;
    private final String nonce;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final long policyVersion;
    private volatile boolean consumed;

    public Challenge(String challengeId, String deviceId, String nonce,
                     Instant issuedAt, Instant expiresAt, long policyVersion) {
        this.challengeId = challengeId;
        this.deviceId = deviceId;
        this.nonce = nonce;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.policyVersion = policyVersion;
    }

    public String challengeId() { return challengeId; }
    public String deviceId() { return deviceId; }
    public String nonce() { return nonce; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public long policyVersion() { return policyVersion; }
    public boolean consumed() { return consumed; }

    public boolean expired(Instant now) {
        return now.isAfter(expiresAt);
    }

    /** CAS 式消费：同一挑战并发提交时只允许一个成功。 */
    public synchronized boolean consume() {
        if (consumed) {
            return false;
        }
        consumed = true;
        return true;
    }
}
