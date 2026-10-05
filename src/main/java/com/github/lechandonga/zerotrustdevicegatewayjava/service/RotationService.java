package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.config.GatewayProperties;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyIds;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyMaterial;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.Challenge;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.DeviceIdentity;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.StoredKey;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SigningPayloads;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.ChallengeStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.DeviceStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.PolicyStore;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * 密钥轮换。
 *
 * <p>过渡期语义：轮换请求必须由旧私钥（当前 ACTIVE 密钥）对
 * “挑战 nonce + 新公钥指纹”签名授权；轮换后旧公钥降为 PREVIOUS，
 * 仅在 gracePeriod 宽限期内可用于证明，到期或显式固化后删除。
 * 轮换时若设备已在实时吊销名单中，则拒绝（吊销设备不得改身份）。
 */
@Service
public class RotationService {

    private final Clock clock;
    private final GatewayProperties properties;
    private final ChallengeStore challengeStore;
    private final DeviceStore deviceStore;
    private final PolicyStore policyStore;

    public RotationService(Clock clock, GatewayProperties properties,
                           ChallengeStore challengeStore, DeviceStore deviceStore,
                           PolicyStore policyStore) {
        this.clock = clock;
        this.properties = properties;
        this.challengeStore = challengeStore;
        this.deviceStore = deviceStore;
        this.policyStore = policyStore;
    }

    /**
     * 执行轮换。同一设备的轮换串行化，保证“当前/上一版”关系始终明确。
     */
    public synchronized DeviceIdentity rotate(String challengeId, String deviceId,
                                              String newKeyAlgorithm, String newPublicKeySpki,
                                              String signatureB64, Duration gracePeriod) {
        Instant now = Instant.now(clock);

        Challenge challenge = challengeStore.find(challengeId)
                .orElseThrow(() -> GatewayException.unauthorized("CHALLENGE_NOT_FOUND",
                        "challenge does not exist: " + challengeId));
        if (!challenge.deviceId().equals(deviceId)) {
            throw GatewayException.unauthorized("CHALLENGE_DEVICE_MISMATCH",
                    "challenge was issued to a different device: " + challenge.deviceId());
        }
        synchronized (challenge) {
            if (challenge.consumed()) {
                throw GatewayException.unauthorized("CHALLENGE_ALREADY_USED",
                        "rotation challenge already consumed; replay is not allowed");
            }
            if (challenge.expired(now)) {
                throw GatewayException.unauthorized("CHALLENGE_EXPIRED",
                        "challenge expired at " + challenge.expiresAt());
            }
        }

        DeviceIdentity device = deviceStore.find(deviceId)
                .orElseThrow(() -> GatewayException.notFound("DEVICE_NOT_FOUND",
                        "device is not enrolled: " + deviceId));

        if (policyStore.current().revokes(deviceId)) {
            throw GatewayException.unauthorized("DEVICE_REVOKED",
                    "revoked device is not allowed to rotate keys");
        }

        KeyMaterial newKey = parseKey(newKeyAlgorithm, newPublicKeySpki);
        if (newKey.keyId().equals(device.active().keyId())
                || (device.previous() != null && newKey.keyId().equals(device.previous().keyId()))) {
            throw GatewayException.badRequest("SAME_KEY_NOT_ALLOWED",
                    "new public key must differ from active and previous keys");
        }

        byte[] signature;
        try {
            signature = Signatures.fromBase64(signatureB64);
        } catch (Exception e) {
            throw GatewayException.badRequest("INVALID_SIGNATURE_ENCODING",
                    "signature is not valid base64");
        }
        byte[] payload = SigningPayloads.rotation(deviceId, challenge.nonce(), newKey.keyId());
        if (!Signatures.verify(device.active().material().publicKey(), payload, signature)) {
            throw GatewayException.unauthorized("INVALID_SIGNATURE",
                    "rotation must be signed by the active key " + device.active().keyId());
        }

        synchronized (challenge) {
            if (!challenge.consume()) {
                throw GatewayException.unauthorized("CHALLENGE_ALREADY_USED",
                        "rotation challenge consumed by a concurrent request");
            }
        }

        Duration grace = gracePeriod != null ? gracePeriod : properties.getDefaultRotationGrace();
        if (grace.isNegative() || grace.isZero()) {
            throw GatewayException.badRequest("INVALID_GRACE_PERIOD",
                    "gracePeriod must be positive");
        }
        DeviceIdentity rotated = device.rotated(new StoredKey(newKey, now), now, now.plus(grace));
        deviceStore.replace(rotated);
        return rotated;
    }

    /** 提前结束过渡期：立即删除旧公钥。 */
    public synchronized DeviceIdentity finalizeRotation(String deviceId) {
        DeviceIdentity device = deviceStore.find(deviceId)
                .orElseThrow(() -> GatewayException.notFound("DEVICE_NOT_FOUND",
                        "device is not enrolled: " + deviceId));
        if (device.previous() == null) {
            throw GatewayException.conflict("NO_PREVIOUS_KEY",
                    "device is not inside a rotation grace period: " + deviceId);
        }
        DeviceIdentity finalized = device.withoutPrevious();
        deviceStore.replace(finalized);
        return finalized;
    }

    private KeyMaterial parseKey(String keyAlgorithm, String publicKeySpki) {
        if (!Signatures.EC.equals(keyAlgorithm) && !Signatures.RSA.equals(keyAlgorithm)) {
            throw GatewayException.badRequest("UNSUPPORTED_KEY_ALGORITHM",
                    "keyAlgorithm must be EC or RSA");
        }
        if (publicKeySpki == null || publicKeySpki.isBlank()) {
            throw GatewayException.badRequest("INVALID_PUBLIC_KEY",
                    "newPublicKeySpki must not be blank");
        }
        try {
            PublicKey publicKey = Signatures.parsePublicKey(keyAlgorithm, publicKeySpki);
            byte[] spki = Signatures.fromBase64(publicKeySpki);
            return new KeyMaterial(KeyIds.of(spki), keyAlgorithm, publicKey, spki);
        } catch (IllegalArgumentException e) {
            throw GatewayException.badRequest("INVALID_PUBLIC_KEY", "publicKeySpki is not valid base64");
        } catch (Exception e) {
            throw GatewayException.badRequest("INVALID_PUBLIC_KEY",
                    "newPublicKeySpki does not encode a valid " + keyAlgorithm + " public key");
        }
    }
}
