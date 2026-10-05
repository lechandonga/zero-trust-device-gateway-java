package com.example.ztgw.service;

import com.example.ztgw.config.ZtgProperties;
import com.example.ztgw.error.ApiException;
import com.example.ztgw.model.Challenge;
import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.store.GatewayStore;
import com.example.ztgw.store.PolicyStore;
import com.example.ztgw.support.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class ChallengeService {

    private static final Logger log = LoggerFactory.getLogger(ChallengeService.class);

    private final GatewayStore store;
    private final PolicyStore policyStore;
    private final TimeService timeService;
    private final ZtgProperties properties;
    private final SecureRandom random = new SecureRandom();

    public ChallengeService(GatewayStore store, PolicyStore policyStore,
                            TimeService timeService, ZtgProperties properties) {
        this.store = store;
        this.policyStore = policyStore;
        this.timeService = timeService;
        this.properties = properties;
    }

    public Challenge issue(String deviceId, Challenge.Purpose purpose) {
        DeviceIdentityRequires.requireEnrolled(store, deviceId);
        byte[] raw = new byte[24];
        random.nextBytes(raw);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String challengeId = "chl_" + KeyIdsShort.of(nonce);
        Instant now = timeService.now();
        PolicySnapshot pinned = policyStore.current();
        Challenge challenge = new Challenge(purpose, challengeId, nonce, deviceId,
                pinned.version(), now, now.plusSeconds(properties.getChallengeTtlSeconds()));
        store.challenges().put(challengeId, challenge);
        log.info("[CHALLENGE] issued {} challenge id={} device={} pinnedPolicy=v{} expiresAt={}",
                purpose, challengeId, deviceId, pinned.version(), challenge.getExpiresAt());
        return challenge;
    }
}
