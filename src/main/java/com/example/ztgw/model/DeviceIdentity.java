package com.example.ztgw.model;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One logical device. Identity ({@code deviceId}) is bound exactly once to a
 * public key. During rotation an additional key state is tracked while the
 * original key stays valid only inside the grace window.
 */
public class DeviceIdentity {

    public enum KeyStatus {
        CURRENT, OLD_GRACE, RETIRED
    }

    public record KeyState(String fingerprint,
                           String publicKeyB64,
                           KeyStatus status,
                           Instant boundAt,
                           Instant retiredAt,
                           Instant graceUntil) {

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("fingerprint", fingerprint);
            map.put("status", status.name());
            map.put("boundAt", boundAt);
            if (retiredAt != null) {
                map.put("retiredAt", retiredAt);
            }
            if (graceUntil != null) {
                map.put("graceUntil", graceUntil);
            }
            return map;
        }
    }

    private final String deviceId;
    private volatile KeyState currentKey;
    private volatile KeyState previousKey;
    private final Instant enrolledAt;
    private final String enrollmentTokenId;
    private volatile boolean revoked;

    public DeviceIdentity(String deviceId, KeyState currentKey, Instant enrolledAt, String enrollmentTokenId) {
        this.deviceId = deviceId;
        this.currentKey = currentKey;
        this.previousKey = null;
        this.enrolledAt = enrolledAt;
        this.enrollmentTokenId = enrollmentTokenId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public KeyState getCurrentKey() {
        return currentKey;
    }

    public KeyState getPreviousKey() {
        return previousKey;
    }

    public Instant getEnrolledAt() {
        return enrolledAt;
    }

    public String getEnrollmentTokenId() {
        return enrollmentTokenId;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void markRevoked() {
        this.revoked = true;
    }

    public synchronized void rotate(KeyState newCurrent, KeyState oldGrace) {
        this.previousKey = oldGrace;
        this.currentKey = newCurrent;
    }

    public synchronized KeyState keyStateFor(String fingerprint, Instant now) {
        if (currentKey != null && currentKey.fingerprint().equals(fingerprint)) {
            return currentKey;
        }
        if (previousKey != null && previousKey.fingerprint().equals(fingerprint)) {
            if (previousKey.status() == KeyStatus.OLD_GRACE
                    && now.isBefore(previousKey.graceUntil())) {
                return previousKey;
            }
        }
        return null;
    }

    public synchronized boolean oldKeyGraceActive(Instant now) {
        return previousKey != null
                && previousKey.status() == KeyStatus.OLD_GRACE
                && now.isBefore(previousKey.graceUntil());
    }
}
