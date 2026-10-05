package com.example.ztgw.service;

import com.example.ztgw.config.ZtgProperties;
import com.example.ztgw.crypto.KeyIds;
import com.example.ztgw.crypto.Signatures;
import com.example.ztgw.error.ApiException;
import com.example.ztgw.model.Challenge;
import com.example.ztgw.model.DecisionRecord;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.model.Session;
import com.example.ztgw.store.GatewayStore;
import com.example.ztgw.store.PolicyStore;
import com.example.ztgw.support.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Service
public class AttestationService {

    private static final Logger log = LoggerFactory.getLogger(AttestationService.class);

    private final GatewayStore store;
    private final PolicyStore policyStore;
    private final TimeService timeService;
    private final ZtgProperties properties;
    private final SecureRandom random = new SecureRandom();

    public AttestationService(GatewayStore store, PolicyStore policyStore,
                              TimeService timeService, ZtgProperties properties) {
        this.store = store;
        this.policyStore = policyStore;
        this.timeService = timeService;
        this.properties = properties;
    }

    public Session attest(String challengeId, String deviceId, String measurement,
                          String publicKeyB64, String signatureB64) {
        Instant now = timeService.now();
        long latestVersion = policyStore.current().version();

        Challenge challenge = store.findChallenge(challengeId).orElse(null);
        if (challenge == null) {
            throw deny(null, deviceId, latestVersion, null, measurement,
                    "CHALLENGE_UNKNOWN", "challenge is not recognized", ApiException::notFound);
        }
        if (challenge.getPurpose() != Challenge.Purpose.ATTEST) {
            throw deny(challenge, deviceId, latestVersion, null, measurement,
                    "CHALLENGE_PURPOSE_MISMATCH", "challenge was not issued for attestation",
                    ApiException::badRequest);
        }
        if (!challenge.getDeviceId().equals(deviceId)) {
            throw deny(challenge, deviceId, latestVersion, null, measurement,
                    "CHALLENGE_DEVICE_MISMATCH", "challenge was issued to another device",
                    ApiException::forbidden);
        }
        if (challenge.getStatus() == Challenge.Status.CONSUMED) {
            throw deny(challenge, deviceId, latestVersion, null, measurement,
                    "CHALLENGE_REPLAY", "challenge has already been consumed and cannot be replayed",
                    ApiException::conflict);
        }
        if (challenge.hasExpired(now)) {
            throw deny(challenge, deviceId, latestVersion, null, measurement,
                    "CHALLENGE_EXPIRED", "challenge expired before proof was submitted",
                    ApiException::forbidden);
        }

        DeviceIdentity identity = DeviceIdentityRequires.requireEnrolled(store, deviceId);
        PublicKey presentedKey = Signatures.parsePublicKey(publicKeyB64);
        String fingerprint = KeyIds.fingerprint(presentedKey);

        PolicySnapshot pinned = policyStore.version(challenge.getPolicyVersion());
        PolicySnapshot latest = policyStore.current();

        if (latest.isRevoked(deviceId)) {
            throw postConsumeDeny(challenge, deviceId, latest.version(), fingerprint, measurement,
                    "DEVICE_REVOKED",
                    "device is on the revocation list of policy v" + latest.version());
        }

        DeviceIdentity.KeyState keyState = identity.keyStateFor(fingerprint, now);
        if (keyState == null) {
            if (identity.getPreviousKey() != null
                    && identity.getPreviousKey().fingerprint().equals(fingerprint)) {
                throw postConsumeDeny(challenge, deviceId, pinned.version(), fingerprint, measurement,
                        "OLD_KEY_GRACE_EXPIRED",
                        "previous key can only attest inside the rotation grace window, which has ended");
            }
            throw postConsumeDeny(challenge, deviceId, pinned.version(), fingerprint, measurement,
                    "DEVICE_KEY_UNKNOWN", "presented key is not bound to this device");
        }

        String payload = Signatures.attestPayload(challengeId, challenge.getNonce(), measurement);
        if (!Signatures.verify(presentedKey, payload, signatureB64)) {
            throw postConsumeDeny(challenge, deviceId, pinned.version(), fingerprint, measurement,
                    "SIGNATURE_INVALID",
                    "signature does not verify against the bound key over challenge nonce and measurement");
        }

        if (!pinned.isTrustedMeasurement(measurement)) {
            throw postConsumeDeny(challenge, deviceId, pinned.version(), fingerprint, measurement,
                    "MEASUREMENT_UNTRUSTED",
                    "firmware measurement is not in the trusted baseline of policy v" + pinned.version());
        }

        if (!challenge.tryConsume()) {
            throw deny(challenge, deviceId, pinned.version(), fingerprint, measurement,
                    "CHALLENGE_REPLAY",
                    "challenge was consumed concurrently; only one submission may succeed",
                    ApiException::conflict);
        }

        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = "sess_" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String decisionId = "dec_" + UUID.randomUUID();
        Instant expiresAt = now.plusSeconds(properties.getSessionTtlSeconds());
        Session session = new Session(token, deviceId, now, expiresAt,
                pinned.version(), fingerprint, measurement, decisionId);
        store.sessions().put(token, session);
        record(new DecisionRecord(decisionId, "ATTEST", deviceId, true, pinned.version(),
                challengeId, fingerprint, measurement,
                "ALLOW: valid signature over one-time challenge; measurement trusted under policy v"
                        + pinned.version(), now));
        log.info("[ATTEST] ALLOW device={} decision={} policy=v{} key={} measurement={} sessionExpiresAt={}",
                deviceId, decisionId, pinned.version(), fingerprint, measurement, expiresAt);
        return session;
    }

    public Map<String, Object> verifySession(String sessionToken) {
        Instant now = timeService.now();
        long latestVersion = policyStore.current().version();
        Session session = store.findSession(sessionToken).orElse(null);
        if (session == null) {
            throw deny(null, null, latestVersion, null, null,
                    "SESSION_UNKNOWN", "session token is not recognized", ApiException::notFound);
        }
        if (session.hasExpired(now)) {
            throw deny(session, latestVersion, "SESSION_EXPIRED", "short-lived session has expired");
        }
        DeviceIdentity identity = store.getDevice(session.getDeviceId());
        if (identity == null || policyStore.current().isRevoked(session.getDeviceId())) {
            throw deny(session, latestVersion, "SESSION_DEVICE_REVOKED",
                    "device was revoked after session issuance; the session is invalidated immediately");
        }
        String decisionId = "dec_" + UUID.randomUUID();
        record(new DecisionRecord(decisionId, "SESSION_VERIFY", session.getDeviceId(), true,
                session.getPolicyVersion(), null, session.getKeyFingerprint(), session.getMeasurement(),
                "ALLOW: session live, device not revoked under policy v" + latestVersion, now));
        return Map.of(
                "valid", true,
                "deviceId", session.getDeviceId(),
                "issuedPolicyVersion", session.getPolicyVersion(),
                "evaluatedPolicyVersion", latestVersion,
                "keyFingerprint", session.getKeyFingerprint(),
                "measurement", session.getMeasurement(),
                "expiresAt", session.getExpiresAt(),
                "decisionId", decisionId);
    }

    private ApiException deny(Session session, long policyVersion, String code, String message) {
        DecisionRecord record = new DecisionRecord("dec_" + UUID.randomUUID(), "SESSION_VERIFY",
                session.getDeviceId(), false, policyVersion, null,
                session.getKeyFingerprint(), session.getMeasurement(), "DENY: " + message, timeService.now());
        record(record);
        return ApiException.forbidden(code, message, Map.of(
                "policyVersion", policyVersion,
                "issuedPolicyVersion", session.getPolicyVersion()));
    }

    private interface ExceptionFactory {
        ApiException create(String code, String message);
    }

    private ApiException deny(Challenge challenge, String deviceId, long policyVersion,
                              String keyFingerprint, String measurement,
                              String code, String message, ExceptionFactory factory) {
        String challengeId = challenge == null ? null : challenge.getChallengeId();
        record(new DecisionRecord("dec_" + UUID.randomUUID(), "ATTEST",
                deviceId, false, policyVersion, challengeId, keyFingerprint, measurement,
                "DENY: " + message, timeService.now()));
        return factory.create(code, message);
    }

    private ApiException postConsumeDeny(Challenge challenge, String deviceId, long policyVersion,
                                         String keyFingerprint, String measurement,
                                         String code, String message) {
        challenge.tryConsume();
        return deny(challenge, deviceId, policyVersion, keyFingerprint, measurement,
                code, message, ApiException::forbidden);
    }

    private void record(DecisionRecord record) {
        store.addDecision(record);
        if (!record.allow()) {
            log.info("[ATTEST] DENY device={} reason={} policy=v{} evidenceChallenge={} key={} measurement={}",
                    record.deviceId(), record.reason(), record.policyVersion(),
                    record.challengeId(), record.keyFingerprint(), record.measurement());
        }
    }
}
