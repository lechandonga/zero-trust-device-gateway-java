package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.config.GatewayProperties;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionEvidence;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionSession;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.Challenge;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.DecisionStep;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.DeviceIdentity;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.PolicySnapshot;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.StoredKey;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SigningPayloads;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.ChallengeStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.DeviceStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.PolicyStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.SessionStore;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;

/**
 * 设备证明与准入会话。
 *
 * <p>规则语义：
 * <ul>
 *   <li>挑战一次性、有时效；同一挑战并发提交时只有一个能消费成功；</li>
 *   <li>签名必须对“挑战 nonce + 设备 + 当前固件度量值”的规范负载有效；</li>
 *   <li>基线与吊销判断使用挑战发放时钉住的策略版本，保证一次证明全程规则一致；</li>
 *   <li>旧密钥仅在轮换宽限期内可用于证明；</li>
 *   <li>每条结论（通过/拒绝）都附带逐环节证据与规则版本。</li>
 * </ul>
 */
@Service
public class AttestationService {

    private final Clock clock;
    private final GatewayProperties properties;
    private final ChallengeStore challengeStore;
    private final DeviceStore deviceStore;
    private final PolicyStore policyStore;
    private final SessionStore sessionStore;

    public AttestationService(Clock clock, GatewayProperties properties,
                              ChallengeStore challengeStore, DeviceStore deviceStore,
                              PolicyStore policyStore, SessionStore sessionStore) {
        this.clock = clock;
        this.properties = properties;
        this.challengeStore = challengeStore;
        this.deviceStore = deviceStore;
        this.policyStore = policyStore;
        this.sessionStore = sessionStore;
    }

    /**
     * 处理一次证明。返回短期会话；失败抛出带证据的 AttestationDeniedException。
     */
    public AdmissionSession attest(String challengeId, String deviceId, String measurement,
                                   String signatureB64, String claimedKeyId, Duration sessionTtl) {
        List<DecisionStep> steps = new ArrayList<>();
        Instant now = Instant.now(clock);

        Challenge challenge = challengeStore.find(challengeId)
                .orElseThrow(() -> deny("CHALLENGE_NOT_FOUND",
                        "challenge does not exist (possible replay of an unknown id)",
                        evidence(challengeId, 0, policyStore.current().version(),
                                deviceId, claimedKeyId, "UNKNOWN", measurement, false, steps)));

        AdmissionEvidence baseEvidence = evidence(challengeId, challenge.policyVersion(),
                challenge.policyVersion(), deviceId, claimedKeyId, "UNKNOWN", measurement, false, steps);

        if (!challenge.deviceId().equals(deviceId)) {
            throw deny("CHALLENGE_DEVICE_MISMATCH",
                    "challenge was issued to a different device: " + challenge.deviceId(), baseEvidence);
        }
        if (challenge.consumed()) {
            throw deny("CHALLENGE_ALREADY_USED",
                    "one-time challenge already consumed; replay is not allowed", baseEvidence);
        }
        if (challenge.expired(now)) {
            throw deny("CHALLENGE_EXPIRED",
                    "challenge expired at " + challenge.expiresAt(), baseEvidence);
        }
        steps.add(DecisionStep.of("challenge_valid", true,
                "one-time, unexpired, bound to device"));

        DeviceIdentity device = deviceStore.find(deviceId)
                .orElseThrow(() -> deny("DEVICE_NOT_FOUND", "device is not enrolled: " + deviceId,
                        baseEvidence));

        PolicySnapshot pinned = policyStore.getVersion(challenge.policyVersion());
        PolicySnapshot live = policyStore.current();
        if (live.revokes(deviceId)) {
            steps.add(DecisionStep.of("device_not_revoked_at_request", false,
                    "device is on the revocation list at policy v" + live.version()));
            throw deny("DEVICE_REVOKED",
                    "device is revoked at policy v" + live.version() + "; no session may be issued",
                    evidence(challengeId, challenge.policyVersion(), live.version(),
                            deviceId, claimedKeyId, "UNKNOWN", measurement, false, steps));
        }
        steps.add(DecisionStep.of("device_not_revoked_at_request", true,
                "not revoked at current policy v" + live.version()));

        byte[] signature;
        try {
            signature = Signatures.fromBase64(signatureB64);
        } catch (Exception e) {
            throw deny("INVALID_SIGNATURE_ENCODING", "signature is not valid base64",
                    withLive(baseEvidence, live.version(), steps));
        }
        byte[] payload = SigningPayloads.attestation(deviceId, challenge.nonce(), measurement);

        ResolvedKey resolved = resolveAndVerify(device, claimedKeyId, payload, signature, now, steps);
        steps.add(DecisionStep.of("signature_valid", true,
                "verified against " + resolved.role + " key " + resolved.key.keyId()));

        boolean baselineMatched = pinned.trustsMeasurement(measurement);
        steps.add(DecisionStep.of("baseline_match", baselineMatched,
                "measurement " + (baselineMatched ? "is" : "is not")
                        + " in trusted baseline of pinned policy v" + pinned.version()));
        if (!baselineMatched) {
            throw deny("MEASUREMENT_UNTRUSTED",
                    "firmware measurement is not in the trusted baseline of policy v"
                            + pinned.version(),
                    evidence(challengeId, pinned.version(), live.version(), deviceId,
                            resolved.key.keyId(), resolved.role, measurement, false, steps));
        }

        boolean pinnedRevoked = pinned.revokes(deviceId);
        steps.add(DecisionStep.of("pinned_policy_revocation", !pinnedRevoked,
                "pinned policy v" + pinned.version()
                        + (pinnedRevoked ? " lists this device as revoked" : " does not revoke this device")));
        if (pinnedRevoked) {
            throw deny("DEVICE_REVOKED_AT_PINNED_POLICY",
                    "device was revoked at the policy version this challenge was issued under (v"
                            + pinned.version() + ")",
                    evidence(challengeId, pinned.version(), live.version(), deviceId,
                            resolved.key.keyId(), resolved.role, measurement, true, steps));
        }

        synchronized (challenge) {
            if (challenge.consumed()) {
                throw deny("CHALLENGE_ALREADY_USED",
                        "one-time challenge consumed by a concurrent request; only one success allowed",
                        evidence(challengeId, pinned.version(), live.version(), deviceId,
                                resolved.key.keyId(), resolved.role, measurement, true, steps));
            }
            challenge.consume();
        }
        steps.add(DecisionStep.of("challenge_consumed", true, "one-time challenge atomically consumed"));

        Instant issuedAt = Instant.now(clock);
        Duration ttl = sessionTtl != null ? sessionTtl : properties.getSessionTtl();
        AdmissionSession session = new AdmissionSession(
                "sess_" + Ids.hex(20),
                deviceId,
                issuedAt,
                issuedAt.plus(ttl),
                evidence(challengeId, pinned.version(), pinned.version(), deviceId,
                        resolved.key.keyId(), resolved.role, measurement, true, steps));
        return sessionStore.put(session);
    }

    private ResolvedKey resolveAndVerify(DeviceIdentity device, String claimedKeyId,
                                         byte[] payload, byte[] signature, Instant now,
                                         List<DecisionStep> steps) {
        StoredKey active = device.active();

        if (claimedKeyId != null) {
            if (claimedKeyId.equals(active.keyId())) {
                if (Signatures.verify(active.material().publicKey(), payload, signature)) {
                    return new ResolvedKey(active, "ACTIVE");
                }
                throw invalidSignature(claimedKeyId, "ACTIVE");
            }
            if (device.previous() != null && claimedKeyId.equals(device.previous().keyId())) {
                if (!device.previousUsable(now)) {
                    throw deny("ROTATION_GRACE_EXPIRED",
                            "previous key is outside the rotation grace period (until "
                                    + device.graceUntil() + ")",
                            evidence(null, 0, policyStore.current().version(), device.deviceId(),
                                    claimedKeyId, "PREVIOUS", null, false, steps));
                }
                if (Signatures.verify(device.previous().material().publicKey(), payload, signature)) {
                    steps.add(DecisionStep.of("rotation_grace", true,
                            "previous key used within grace period until " + device.graceUntil()));
                    return new ResolvedKey(device.previous(), "PREVIOUS");
                }
                throw invalidSignature(claimedKeyId, "PREVIOUS");
            }
            throw GatewayException.unauthorized("KEY_NOT_BOUND",
                    "claimed keyId is not bound to this device: " + claimedKeyId);
        }

        if (Signatures.verify(active.material().publicKey(), payload, signature)) {
            return new ResolvedKey(active, "ACTIVE");
        }
        if (device.previousUsable(now)
                && Signatures.verify(device.previous().material().publicKey(), payload, signature)) {
            steps.add(DecisionStep.of("rotation_grace", true,
                    "previous key used within grace period until " + device.graceUntil()));
            return new ResolvedKey(device.previous(), "PREVIOUS");
        }
        if (device.previous() != null && !device.previousUsable(now)) {
            steps.add(DecisionStep.of("rotation_grace", false,
                    "previous key exists but grace period ended at " + device.graceUntil()));
        }
        throw invalidSignature(active.keyId(), "ACTIVE");
    }

    private AttestationDeniedException invalidSignature(String keyId, String role) {
        return new AttestationDeniedException("INVALID_SIGNATURE",
                "signature does not verify against " + role + " key " + keyId,
                org.springframework.http.HttpStatus.UNAUTHORIZED, null);
    }

    private AttestationDeniedException deny(String code, String message, AdmissionEvidence evidence) {
        return new AttestationDeniedException(code, message,
                org.springframework.http.HttpStatus.UNAUTHORIZED, evidence);
    }

    private AdmissionEvidence withLive(AdmissionEvidence evidence, long liveVersion,
                                       List<DecisionStep> steps) {
        return new AdmissionEvidence(evidence.challengeId(), evidence.challengePolicyVersion(),
                liveVersion, evidence.deviceId(), evidence.keyId(), evidence.keyRole(),
                evidence.measurement(), false, evidence.deviceRevokedAtDecision(), steps);
    }

    private AdmissionEvidence evidence(String challengeId, long challengeVersion, long liveVersion,
                                       String deviceId, String keyId, String keyRole,
                                       String measurement, boolean baselineMatched,
                                       List<DecisionStep> steps) {
        boolean revoked = deviceId != null && policyStore.current().revokes(deviceId);
        return new AdmissionEvidence(challengeId == null ? "n/a" : challengeId,
                challengeVersion, liveVersion, deviceId == null ? "n/a" : deviceId,
                keyId == null ? "n/a" : keyId, keyRole, measurement == null ? "n/a" : measurement,
                baselineMatched, revoked, List.copyOf(steps));
    }

    private record ResolvedKey(StoredKey key, String role) {
    }
}
