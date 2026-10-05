package com.github.lechandonga.zerotrustdevicegatewayjava.web.dto;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionEvidence;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionSession;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.Challenge;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.DeviceIdentity;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.EnrollmentToken;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.PolicySnapshot;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/** 对外响应视图。 */
public final class Views {

    private Views() {
    }

    public record ErrorResponse(String code, String message, AdmissionEvidence evidence) {
    }

    public record TokenView(String token, String expectedDeviceId, Instant issuedAt,
                            Instant expiresAt, boolean consumed, String consumedBy) {
        public static TokenView of(EnrollmentToken token) {
            return new TokenView(token.value(), token.expectedDeviceId(), token.issuedAt(),
                    token.expiresAt(), token.consumed(), token.consumedBy());
        }
    }

    public record DeviceView(String deviceId, String activeKeyId, String previousKeyId,
                             Instant graceUntil, Instant rotatedAt, Instant enrolledAt) {
        public static DeviceView of(DeviceIdentity device) {
            return new DeviceView(device.deviceId(), device.active().keyId(),
                    device.previous() != null ? device.previous().keyId() : null,
                    device.graceUntil(), device.rotatedAt(), device.enrolledAt());
        }
    }

    public record ChallengeView(String challengeId, String deviceId, String nonce,
                                Instant issuedAt, Instant expiresAt, long policyVersion) {
        public static ChallengeView of(Challenge challenge) {
            return new ChallengeView(challenge.challengeId(), challenge.deviceId(), challenge.nonce(),
                    challenge.issuedAt(), challenge.expiresAt(), challenge.policyVersion());
        }
    }

    public record SessionView(String sessionId, String deviceId, Instant issuedAt,
                              Instant expiresAt, boolean valid, Long livePolicyVersion,
                              AdmissionEvidence evidence) {
        public static SessionView admitted(AdmissionSession session, long livePolicyVersion) {
            return new SessionView(session.sessionId(), session.deviceId(), session.issuedAt(),
                    session.expiresAt(), true, livePolicyVersion, session.evidence());
        }
    }

    public record PolicyView(long version, Instant createdAt, Set<String> trustedMeasurements,
                             Set<String> revokedDevices, String note) {
        public static PolicyView of(PolicySnapshot snapshot) {
            return new PolicyView(snapshot.version(), snapshot.createdAt(),
                    snapshot.trustedMeasurements(), snapshot.revokedDevices(), snapshot.note());
        }
    }

    public record PolicyHistory(List<PolicyView> versions) {
    }
}
