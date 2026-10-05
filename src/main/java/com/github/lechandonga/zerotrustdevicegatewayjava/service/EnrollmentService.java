package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.config.GatewayProperties;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyIds;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.KeyMaterial;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.DeviceIdentity;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.EnrollmentToken;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.StoredKey;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.DeviceStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.TokenStore;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 首次入网与身份绑定。
 */
@Service
public class EnrollmentService {

    private final Clock clock;
    private final GatewayProperties properties;
    private final TokenStore tokenStore;
    private final DeviceStore deviceStore;
    private final Set<String> knownKeyIds = ConcurrentHashMap.newKeySet();

    public EnrollmentService(Clock clock, GatewayProperties properties,
                             TokenStore tokenStore, DeviceStore deviceStore) {
        this.clock = clock;
        this.properties = properties;
        this.tokenStore = tokenStore;
        this.deviceStore = deviceStore;
    }

    /** 管理侧签发一次性入网令牌。 */
    public EnrollmentToken issueToken(String tokenValue, String expectedDeviceId, Duration ttl) {
        if (tokenValue == null || tokenValue.isBlank()) {
            throw GatewayException.badRequest("INVALID_TOKEN", "token value must not be blank");
        }
        if (tokenStore.find(tokenValue).isPresent()) {
            throw GatewayException.conflict("TOKEN_EXISTS", "token already issued: " + tokenValue);
        }
        Duration effectiveTtl = ttl != null ? ttl : properties.getEnrollmentTtl();
        Instant now = Instant.now(clock);
        return tokenStore.put(new EnrollmentToken(tokenValue, expectedDeviceId, now, now.plus(effectiveTtl)));
    }

    public EnrollmentToken issueToken(String tokenValue, String expectedDeviceId) {
        return issueToken(tokenValue, expectedDeviceId, null);
    }

    /**
     * 设备凭一次性令牌换取登记。
     * 同步执行以串行化并发首次登记；失败原因按令牌状态可区分。
     */
    public synchronized DeviceIdentity enroll(String tokenValue, String deviceId,
                                              String keyAlgorithm, String publicKeySpki) {
        if (deviceId == null || deviceId.isBlank()) {
            throw GatewayException.badRequest("INVALID_REQUEST", "deviceId must not be blank");
        }
        if (deviceStore.find(deviceId).isPresent()) {
            throw GatewayException.conflict("DEVICE_ALREADY_ENROLLED",
                    "device already enrolled, existing identity and public key are never overwritten: "
                            + deviceId);
        }

        EnrollmentToken token = tokenStore.find(tokenValue)
                .orElseThrow(() -> GatewayException.unauthorized("TOKEN_MISMATCH",
                        "enrollment token does not match any issued token"));

        Instant now = Instant.now(clock);
        if (token.consumed()) {
            throw GatewayException.unauthorized("TOKEN_ALREADY_USED",
                    "one-time token already consumed by device: " + token.consumedBy());
        }
        if (token.expectedDeviceId() != null && !token.expectedDeviceId().equals(deviceId)) {
            throw GatewayException.unauthorized("TOKEN_DEVICE_MISMATCH",
                    "token is bound to a different device: " + token.expectedDeviceId());
        }
        if (token.expired(now)) {
            throw GatewayException.unauthorized("TOKEN_EXPIRED",
                    "token expired at " + token.expiresAt());
        }

        KeyMaterial keyMaterial = parseKey(keyAlgorithm, publicKeySpki);
        if (!knownKeyIds.add(keyMaterial.keyId())) {
            throw GatewayException.conflict("PUBLIC_KEY_ALREADY_BOUND",
                    "public key is already bound to another device identity");
        }

        DeviceIdentity identity = DeviceIdentity.firstEnrollment(
                deviceId, new StoredKey(keyMaterial, now), now);
        if (!deviceStore.registerIfAbsent(identity)) {
            knownKeyIds.remove(keyMaterial.keyId());
            throw GatewayException.conflict("DEVICE_ALREADY_ENROLLED",
                    "device already enrolled, existing identity and public key are never overwritten: "
                            + deviceId);
        }
        if (!token.markConsumed(now, deviceId)) {
            throw GatewayException.unauthorized("TOKEN_ALREADY_USED",
                    "one-time token already consumed by device: " + token.consumedBy());
        }
        return identity;
    }

    private KeyMaterial parseKey(String keyAlgorithm, String publicKeySpki) {
        if (!Signatures.EC.equals(keyAlgorithm) && !Signatures.RSA.equals(keyAlgorithm)) {
            throw GatewayException.badRequest("UNSUPPORTED_KEY_ALGORITHM",
                    "keyAlgorithm must be EC or RSA");
        }
        if (publicKeySpki == null || publicKeySpki.isBlank()) {
            throw GatewayException.badRequest("INVALID_PUBLIC_KEY", "publicKeySpki must not be blank");
        }
        try {
            PublicKey publicKey = Signatures.parsePublicKey(keyAlgorithm, publicKeySpki);
            byte[] spki = Signatures.fromBase64(publicKeySpki);
            return new KeyMaterial(KeyIds.of(spki), keyAlgorithm, publicKey, spki);
        } catch (IllegalArgumentException e) {
            throw GatewayException.badRequest("INVALID_PUBLIC_KEY", "publicKeySpki is not valid base64");
        } catch (Exception e) {
            throw GatewayException.badRequest("INVALID_PUBLIC_KEY",
                    "publicKeySpki does not encode a valid " + keyAlgorithm + " public key");
        }
    }

}
