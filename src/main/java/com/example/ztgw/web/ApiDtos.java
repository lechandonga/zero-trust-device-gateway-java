package com.example.ztgw.web;

import java.util.Set;

final class ApiDtos {

    private ApiDtos() {
    }

    record IssueTokenRequest(String deviceId) {
    }

    record EnrollRequest(String deviceId, String token, String publicKey) {
    }

    record ChallengeRequest(String deviceId, String purpose) {
    }

    record AttestRequest(String challengeId, String deviceId, String measurement,
                         String publicKey, String signature) {
    }

    record RotateRequest(String challengeId, String deviceId, String oldPublicKey,
                         String newPublicKey, String signature) {
    }

    record VerifySessionRequest(String sessionToken) {
    }

    record PolicyUpdateRequest(Long expectedVersion,
                               Set<String> trustedMeasurements,
                               Set<String> revokedDevices,
                               String reason) {
    }
}
