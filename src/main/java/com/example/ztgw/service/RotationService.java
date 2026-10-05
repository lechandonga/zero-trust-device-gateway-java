package com.example.ztgw.service;

import com.example.ztgw.config.ZtgProperties;
import com.example.ztgw.crypto.KeyIds;
import com.example.ztgw.crypto.Signatures;
import com.example.ztgw.error.ApiException;
import com.example.ztgw.model.Challenge;
import com.example.ztgw.model.DecisionRecord;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.store.GatewayStore;
import com.example.ztgw.store.PolicyStore;
import com.example.ztgw.support.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class RotationService {

    private static final Logger log = LoggerFactory.getLogger(RotationService.class);

    private final GatewayStore store;
    private final PolicyStore policyStore;
    private final TimeService timeService;
    private final ZtgProperties properties;

    public RotationService(GatewayStore store, PolicyStore policyStore,
                           TimeService timeService, ZtgProperties properties) {
        this.store = store;
        this.policyStore = policyStore;
        this.timeService = timeService;
        this.properties = properties;
    }

    public Map<String, Object> rotate(String challengeId, String deviceId,
                                      String oldPublicKeyB64, String newPublicKeyB64,
                                      String signatureB64) {
        Instant now = timeService.now();
        Challenge challenge = store.findChallenge(challengeId)
                .orElseThrow(() -> ApiException.notFound("CHALLENGE_UNKNOWN", "challenge is not recognized"));
        if (challenge.getPurpose() != Challenge.Purpose.ROTATE) {
            throw ApiException.badRequest("CHALLENGE_PURPOSE_MISMATCH",
                    "challenge was not issued for key rotation");
        }
        if (!challenge.getDeviceId().equals(deviceId)) {
            throw ApiException.forbidden("CHALLENGE_DEVICE_MISMATCH",
                    "challenge was issued to another device");
        }
        if (challenge.getStatus() == Challenge.Status.CONSUMED) {
            throw ApiException.conflict("CHALLENGE_REPLAY",
                    "rotation challenge has already been consumed and cannot be replayed");
        }
        if (challenge.hasExpired(now)) {
            throw ApiException.forbidden("CHALLENGE_EXPIRED",
                    "rotation challenge expired before proof was submitted");
        }

        DeviceIdentity identity = DeviceIdentityRequires.requireEnrolled(store, deviceId);
        PolicySnapshot latest = policyStore.current();
        if (latest.isRevoked(deviceId)) {
            throw ApiException.forbidden("DEVICE_REVOKED", "revoked devices may not rotate keys");
        }

        PublicKey oldKey = Signatures.parsePublicKey(oldPublicKeyB64);
        PublicKey newKey = Signatures.parsePublicKey(newPublicKeyB64);
        String oldFingerprint = KeyIds.fingerprint(oldKey);
        String newFingerprint = KeyIds.fingerprint(newKey);

        if (!identity.getCurrentKey().fingerprint().equals(oldFingerprint)) {
            throw ApiException.forbidden("ROTATION_SIGNER_NOT_CURRENT",
                    "rotation must be authorized by the device's current key, not a retired or grace key");
        }
        if (newFingerprint.equals(oldFingerprint)) {
            throw ApiException.conflict("ROTATION_SAME_KEY", "new key must differ from the current key");
        }
        if (identity.getPreviousKey() != null
                && identity.getPreviousKey().fingerprint().equals(newFingerprint)) {
            throw ApiException.conflict("ROTATION_KEY_SEEN",
                    "new key was previously used by this device and cannot be re-bound");
        }

        String payload = Signatures.rotationPayload(challengeId, challenge.getNonce(),
                oldFingerprint, newFingerprint);
        if (!Signatures.verify(oldKey, payload, signatureB64)) {
            throw ApiException.forbidden("SIGNATURE_INVALID",
                    "rotation signature does not verify against the current key");
        }
        if (!challenge.tryConsume()) {
            throw ApiException.conflict("CHALLENGE_REPLAY",
                    "rotation challenge was consumed concurrently; only one submission may succeed");
        }

        Instant graceUntil = now.plusSeconds(properties.getRotationGraceSeconds());
        DeviceIdentity.KeyState oldGrace = new DeviceIdentity.KeyState(
                oldFingerprint, oldPublicKeyB64, DeviceIdentity.KeyStatus.OLD_GRACE,
                identity.getCurrentKey().boundAt(), now, graceUntil);
        DeviceIdentity.KeyState newCurrent = new DeviceIdentity.KeyState(
                newFingerprint, newPublicKeyB64, DeviceIdentity.KeyStatus.CURRENT, now, null, null);
        identity.rotate(newCurrent, oldGrace);

        String decisionId = "dec_" + UUID.randomUUID();
        store.addDecision(new DecisionRecord(decisionId, "ROTATE", deviceId, true, latest.version(),
                challengeId, newFingerprint, null,
                "ALLOW: current key signed new key binding; old key kept in grace until " + graceUntil, now));
        log.info("[ROTATE] ALLOW device={} decision={} newKey={} oldKeyGraceUntil={} policy=v{}",
                deviceId, decisionId, newFingerprint, graceUntil, latest.version());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("deviceId", deviceId);
        response.put("currentKey", newCurrent.toMap());
        response.put("previousKey", oldGrace.toMap());
        response.put("graceSeconds", properties.getRotationGraceSeconds());
        response.put("decisionId", decisionId);
        response.put("policyVersion", latest.version());
        return response;
    }

    /** Promote the grace/retired state from OLD_GRACE to RETIRED once the window ends. */
    public void expireGraceIfDue(DeviceIdentity identity, Instant now) {
        DeviceIdentity.KeyState previous = identity.getPreviousKey();
        if (previous != null
                && previous.status() == DeviceIdentity.KeyStatus.OLD_GRACE
                && !now.isBefore(previous.graceUntil())) {
            identity.rotate(identity.getCurrentKey(),
                    new DeviceIdentity.KeyState(previous.fingerprint(), previous.publicKeyB64(),
                            DeviceIdentity.KeyStatus.RETIRED, previous.boundAt(),
                            previous.retiredAt(), previous.graceUntil()));
        }
    }
}
