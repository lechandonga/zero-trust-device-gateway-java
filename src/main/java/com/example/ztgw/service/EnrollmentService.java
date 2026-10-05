package com.example.ztgw.service;

import com.example.ztgw.config.ZtgProperties;
import com.example.ztgw.crypto.KeyIds;
import com.example.ztgw.crypto.Signatures;
import com.example.ztgw.error.ApiException;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.model.EnrollmentToken;
import com.example.ztgw.store.GatewayStore;
import com.example.ztgw.support.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class EnrollmentService {

    private static final Logger log = LoggerFactory.getLogger(EnrollmentService.class);

    private final GatewayStore store;
    private final TimeService timeService;
    private final ZtgProperties properties;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Object> deviceLocks = new ConcurrentHashMap<>();

    public EnrollmentService(GatewayStore store, TimeService timeService, ZtgProperties properties) {
        this.store = store;
        this.timeService = timeService;
        this.properties = properties;
    }

    public EnrollmentToken issueToken(String deviceId) {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = "tok_" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Instant now = timeService.now();
        EnrollmentToken enrollmentToken = new EnrollmentToken(
                token, deviceId, now, now.plusSeconds(properties.getTokenTtlSeconds()));
        store.tokens().put(token, enrollmentToken);
        log.info("[ENROLL] issued one-time token id={} boundDevice={} expiresAt={}",
                token, deviceId, enrollmentToken.getExpiresAt());
        return enrollmentToken;
    }

    public DeviceIdentity enroll(String deviceId, String tokenValue, String publicKeyB64) {
        Instant now = timeService.now();
        EnrollmentToken token = store.tokens().get(tokenValue);
        if (token == null) {
            throw ApiException.notFound("TOKEN_UNKNOWN", "enrollment token is not recognized");
        }
        if (token.getBoundDeviceId() != null && !token.getBoundDeviceId().equals(deviceId)) {
            throw ApiException.forbidden("TOKEN_DEVICE_MISMATCH",
                    "token was issued for a different device",
                    Map.of("expectedDevice", token.getBoundDeviceId(), "presentedDevice", deviceId));
        }
        if (token.getStatus() == EnrollmentToken.Status.CONSUMED) {
            throw ApiException.conflict("TOKEN_ALREADY_USED",
                    "token has already been consumed and cannot be reused",
                    Map.of("consumedAt", token.getConsumedAt(), "consumedBy", token.getConsumedByDevice()));
        }
        if (token.hasExpired(now)) {
            throw ApiException.forbidden("TOKEN_EXPIRED",
                    "token expired before it was consumed",
                    Map.of("expiresAt", token.getExpiresAt(), "now", now));
        }

        Object lock = deviceLocks.computeIfAbsent(deviceId, key -> new Object());
        synchronized (lock) {
            DeviceIdentity existing = store.getDevice(deviceId);
            if (existing != null) {
                throw ApiException.conflict("DEVICE_ALREADY_ENROLLED",
                        "device identity is already bound; repeated enrollment cannot overwrite its public key",
                        Map.of("boundKeyFingerprint", existing.getCurrentKey().fingerprint()));
            }
            if (!token.consume(deviceId)) {
                throw ApiException.conflict("TOKEN_ALREADY_USED",
                        "token was consumed concurrently by another request");
            }
            PublicKey publicKey = Signatures.parsePublicKey(publicKeyB64);
            String fingerprint = KeyIds.fingerprint(publicKey);
            DeviceIdentity.KeyState keyState = new DeviceIdentity.KeyState(
                    fingerprint, publicKeyB64, DeviceIdentity.KeyStatus.CURRENT, now, null, null);
            DeviceIdentity identity = new DeviceIdentity(deviceId, keyState, now, token.getToken());
            store.devices().put(deviceId, identity);
            log.info("[ENROLL] device={} bound to key={} (identity created, token consumed once)",
                    deviceId, fingerprint);
            return identity;
        }
    }
}
