package com.github.lechandonga.zerotrustdevicegatewayjava.web.dto;

import java.time.Duration;
import java.util.List;

/** 所有 HTTP 请求体记录，集中放置。 */
public final class Requests {

    private Requests() {
    }

    public record IssueTokenRequest(String token, String expectedDeviceId, Duration ttl) {
    }

    public record EnrollRequest(String token, String deviceId,
                                String keyAlgorithm, String publicKeySpki) {
    }

    public record ChallengeRequest(String deviceId) {
    }

    public record AttestRequest(String challengeId, String deviceId, String measurement,
                                String signature, String keyId, Duration sessionTtl) {
    }

    public record RotateRequest(String challengeId, String deviceId, String newKeyAlgorithm,
                                String newPublicKeySpki, String signature, Duration gracePeriod) {
    }

    public record PublishPolicyRequest(List<String> trustedMeasurements,
                                       List<String> revokedDevices, String note) {
    }

    public record RevokeRequest(String deviceId, String note) {
    }

    public record UnrevokeRequest(String deviceId, String note) {
    }
}
