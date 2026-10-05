package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.config.GatewayProperties;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.Challenge;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.ChallengeStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.DeviceStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.PolicyStore;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

/**
 * 下发一次性、有时效的挑战，并在发放瞬间钉住当前策略版本。
 */
@Service
public class ChallengeService {

    private final Clock clock;
    private final GatewayProperties properties;
    private final ChallengeStore challengeStore;
    private final DeviceStore deviceStore;
    private final PolicyStore policyStore;

    public ChallengeService(Clock clock, GatewayProperties properties,
                            ChallengeStore challengeStore, DeviceStore deviceStore,
                            PolicyStore policyStore) {
        this.clock = clock;
        this.properties = properties;
        this.challengeStore = challengeStore;
        this.deviceStore = deviceStore;
        this.policyStore = policyStore;
    }

    public Challenge issue(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            throw GatewayException.badRequest("INVALID_REQUEST", "deviceId must not be blank");
        }
        deviceStore.find(deviceId)
                .orElseThrow(() -> GatewayException.notFound("DEVICE_NOT_FOUND",
                        "device is not enrolled: " + deviceId));
        Instant now = Instant.now(clock);
        long policyVersion = policyStore.current().version();
        return challengeStore.put(new Challenge(
                "ch_" + Ids.hex(16),
                deviceId,
                Ids.hex(24),
                now,
                now.plus(properties.getChallengeTtl()),
                policyVersion));
    }
}
