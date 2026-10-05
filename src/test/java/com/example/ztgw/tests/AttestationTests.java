package com.example.ztgw.tests;

import com.example.ztgw.support.TimeService;
import com.example.ztgw.tests.support.BusinessCaseLogger;
import com.example.ztgw.tests.support.PolicyAdmin;
import com.example.ztgw.tests.support.SimulatedDevice;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(BusinessCaseLogger.class)
class AttestationTests {

    private static final String FW = "sha256:fw-good-1";

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private TimeService clock;

    private SimulatedDevice device;

    @BeforeEach
    void setUp() {
        device = new SimulatedDevice(rest, "dev-attest-" + System.nanoTime(), FW);
        device.enroll();
        PolicyAdmin.publish(rest, Set.of(FW), Set.of(), "trust baseline fw-good-1");
    }

    @Test
    void validProofYieldsShortLivedSession() {
        String session = device.attestAndGetSession();
        assertNotNull(session);
        ResponseEntity<Map> verify = device.verifySessionRaw(session);
        assertEquals(200, verify.getStatusCode().value());
        assertEquals(true, verify.getBody().get("valid"));
        assertNotNull(verify.getBody().get("decisionId"));
    }

    @Test
    void replayedChallengeRejected() {
        Map<String, Object> challenge = device.challenge("ATTEST");
        assertEquals(200, device.attestRaw(challenge).getStatusCode().value());
        ResponseEntity<Map> replay = device.attestRaw(challenge);
        assertEquals(409, replay.getStatusCode().value());
        assertEquals("CHALLENGE_REPLAY", replay.getBody().get("code"));
    }

    @Test
    void expiredChallengeRejected() {
        Map<String, Object> challenge = device.challenge("ATTEST");
        clock.advance(Duration.ofSeconds(3));
        ResponseEntity<Map> response = device.attestRaw(challenge);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("CHALLENGE_EXPIRED", response.getBody().get("code"));
    }

    @Test
    void invalidSignatureRejected() {
        Map<String, Object> challenge = device.challenge("ATTEST");
        KeyPair attacker = SimulatedDevice.generateKeyPair();
        ResponseEntity<Map> response = device.attestWithRawSigner(challenge, attacker);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("DEVICE_KEY_UNKNOWN", response.getBody().get("code"));

        Map<String, Object> another = device.challenge("ATTEST");
        String payload = com.example.ztgw.crypto.Signatures
                .attestPayload((String) another.get("challengeId"),
                        (String) another.get("nonce"), FW) + "-tampered";
        String badSignature = com.example.ztgw.crypto.Signatures
                .sign(device.getKeyPair().getPrivate(), payload);
        ResponseEntity<Map> badSig = rest.postForEntity("/api/devices/attest", Map.of(
                "challengeId", another.get("challengeId"),
                "deviceId", device.getDeviceId(),
                "measurement", FW,
                "publicKey", device.getPublicKeyB64(),
                "signature", badSignature), Map.class);
        assertEquals(403, badSig.getStatusCode().value());
        assertEquals("SIGNATURE_INVALID", badSig.getBody().get("code"));
    }

    @Test
    void untrustedMeasurementRejected() {
        device.setFirmwareMeasurement("sha256:fw-evil");
        Map<String, Object> challenge = device.challenge("ATTEST");
        ResponseEntity<Map> response = device.attestRaw(challenge);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("MEASUREMENT_UNTRUSTED", response.getBody().get("code"));
    }

    @Test
    void expiredSessionRejected() {
        String session = device.attestAndGetSession();
        clock.advance(Duration.ofSeconds(4));
        ResponseEntity<Map> response = device.verifySessionRaw(session);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("SESSION_EXPIRED", response.getBody().get("code"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void concurrentSubmissionsOfSameChallengeOnlyOneSucceeds() throws Exception {
        Map<String, Object> challenge = device.challenge("ATTEST");
        int threads = 8;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    ResponseEntity<Map> response = device.attestRaw(challenge);
                    if (response.getStatusCode().is2xxSuccessful()) {
                        success.incrementAndGet();
                    } else if ("CHALLENGE_REPLAY".equals(response.getBody().get("code"))) {
                        rejected.incrementAndGet();
                    }
                } catch (Exception ignored) {
                    // counted as neither; assertions below guarantee the expected split
                }
            });
        }
        ready.await(5, TimeUnit.SECONDS);
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        assertEquals(1, success.get(), "exactly one concurrent proof must succeed");
        assertEquals(threads - 1, rejected.get(), "all losers must be told it is a replay");
    }

    @Test
    @SuppressWarnings("unchecked")
    void policySwitchDoesNotRewritePinnedAdmission() {
        Map<String, Object> challenge = device.challenge("ATTEST");
        long pinnedVersion = ((Number) challenge.get("policyVersion")).longValue();
        PolicyAdmin.publish(rest, Set.of("sha256:totally-different-fw"), Set.of(),
                "baseline switched after challenge issued");

        ResponseEntity<Map> response = device.attestRaw(challenge);
        assertEquals(200, response.getStatusCode().value(),
                "proof is judged against the version pinned at challenge issuance");
        assertEquals(pinnedVersion, ((Number) response.getBody().get("policyVersion")).longValue());

        ResponseEntity<List> decisions = rest.getForEntity("/api/admin/decisions?limit=5", List.class);
        Map<String, Object> allow = (Map<String, Object>) decisions.getBody().get(0);
        assertEquals(true, allow.get("allow"));
        assertEquals(pinnedVersion, ((Number) allow.get("policyVersion")).longValue());
        assertNotNull(allow.get("challengeId"));
        assertNotNull(allow.get("measurement"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void policyUpdateWithStaleVersionRejected() {
        long current = PolicyAdmin.currentVersion(rest);
        PolicyAdmin.publish(rest, Set.of(FW, "sha256:fw-2"), Set.of(), "interim update");
        ResponseEntity<Map> stale = rest.postForEntity("/api/admin/policy", Map.of(
                "expectedVersion", current,
                "trustedMeasurements", Set.of(FW),
                "revokedDevices", Set.of(),
                "reason", "stale client update"), Map.class);
        assertEquals(412, stale.getStatusCode().value());
        assertEquals("POLICY_VERSION_CONFLICT", stale.getBody().get("code"));
    }
}
