package com.github.lechandonga.zerotrustdevicegatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SimulatedDevice;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SigningPayloads;
import com.github.lechandonga.zerotrustdevicegatewayjava.tests.support.ApiTestBase;
import com.github.lechandonga.zerotrustdevicegatewayjava.tests.support.BusinessDomain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessDomain("设备证明与准入会话")
class AttestationFlowTests extends ApiTestBase {

    private static final String TRUSTED_MEASUREMENT =
            "a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff00";

    private SimulatedDevice enrolledDevice(String id) {
        SimulatedDevice device = new SimulatedDevice(id, TRUSTED_MEASUREMENT);
        String token = "TOKEN-ATT-" + id;
        issueToken(token, id);
        enroll(device, token);
        return device;
    }

    @Test
    @DisplayName("证明-01: 合法签名+受信度量换取会话，证据指向正确策略版本与 ACTIVE 密钥")
    void validAttestationIssuesSession() {
        SimulatedDevice device = enrolledDevice("att-ok-01");
        JsonNode challenge = challenge(device.deviceId());

        var response = post("/api/attestations", attestRequest(device, challenge, true));

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        JsonNode session = response.getBody();
        assertNotNull(session.get("sessionId"));
        JsonNode evidence = session.get("evidence");
        assertEquals(device.activePublic().keyId(), evidence.get("keyId").asText());
        assertEquals("ACTIVE", evidence.get("keyRole").asText());
        assertTrue(evidence.get("baselineMatched").asBoolean());
        assertEquals(challenge.get("policyVersion").asLong(),
                evidence.get("challengePolicyVersion").asLong());
    }

    @Test
    @DisplayName("证明-02: 重放同一挑战被拒（CHALLENGE_ALREADY_USED）")
    void replayRejected() {
        SimulatedDevice device = enrolledDevice("att-replay-02");
        JsonNode challenge = challenge(device.deviceId());
        var request = attestRequest(device, challenge, true);

        assertEquals(HttpStatus.CREATED, post("/api/attestations", request).getStatusCode());
        var replay = post("/api/attestations", request);

        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        assertEquals("CHALLENGE_ALREADY_USED", replay.getBody().get("code").asText());
    }

    @Test
    @DisplayName("证明-03: 过期挑战被拒（CHALLENGE_EXPIRED）")
    void expiredChallengeRejected() throws Exception {
        SimulatedDevice device = enrolledDevice("att-expired-03");
        JsonNode challenge = challenge(device.deviceId());
        Thread.sleep(2200);

        var response = post("/api/attestations", attestRequest(device, challenge, true));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("CHALLENGE_EXPIRED", response.getBody().get("code").asText());
    }

    @Test
    @DisplayName("证明-04: 度量值与受信基线不符被拒（MEASUREMENT_UNTRUSTED），证据 baselineMatched=false")
    void untrustedMeasurementRejected() {
        SimulatedDevice device = enrolledDevice("att-measure-04");
        JsonNode challenge = challenge(device.deviceId());
        byte[] payload = SigningPayloads.attestation(
                device.deviceId(), challenge.get("nonce").asText(), "tampered-firmware-value");
        byte[] signature = device.signWithActive(payload);

        var response = post("/api/attestations", attestRequestCustom(
                device, challenge, "tampered-firmware-value", signature,
                device.activePublic().keyId()));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("MEASUREMENT_UNTRUSTED", response.getBody().get("code").asText());
        JsonNode evidence = response.getBody().get("evidence");
        assertEquals(false, evidence.get("baselineMatched").asBoolean());
        assertTrue(evidence.get("steps").isArray());
    }

    @Test
    @DisplayName("证明-05: 伪造签名被拒（INVALID_SIGNATURE），挑战未消费，可随后合法重试")
    void invalidSignatureRejectedAndChallengeStillUsable() {
        SimulatedDevice device = enrolledDevice("att-sig-05");
        JsonNode challenge = challenge(device.deviceId());

        byte[] wrongPayload = SigningPayloads.attestation(
                device.deviceId(), "some-other-nonce", device.firmwareMeasurement());
        var bad = post("/api/attestations", attestRequestCustom(
                device, challenge, device.firmwareMeasurement(),
                device.signWithActive(wrongPayload), device.activePublic().keyId()));
        assertEquals(HttpStatus.UNAUTHORIZED, bad.getStatusCode());
        assertEquals("INVALID_SIGNATURE", bad.getBody().get("code").asText());

        var retry = post("/api/attestations", attestRequest(device, challenge, true));
        assertEquals(HttpStatus.CREATED, retry.getStatusCode());
    }

    @Test
    @DisplayName("证明-06: 同一挑战并发提交时只有一个成功，其余 CHALLENGE_ALREADY_USED")
    void concurrentSameChallengeOnlyOneSucceeds() throws Exception {
        SimulatedDevice device = enrolledDevice("att-concurrent-06");
        JsonNode challenge = challenge(device.deviceId());

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    var response = post("/api/attestations",
                            attestRequest(device, challenge, true));
                    if (response.getStatusCode() == HttpStatus.CREATED) {
                        success.incrementAndGet();
                    } else if ("CHALLENGE_ALREADY_USED"
                            .equals(response.getBody().get("code").asText())) {
                        rejected.incrementAndGet();
                    }
                } catch (Exception ignored) {
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(1, success.get(), "恰好一个并发证明成功");
        assertEquals(threads - 1, rejected.get(), "其余全部因一次性消费被拒");
    }

    @Test
    @DisplayName("证明-07: 设备被吊销后已发放会话立即失效（SESSION_REVOKED），且新证明被拒")
    void revokedDeviceSessionsInvalidImmediately() {
        SimulatedDevice device = enrolledDevice("att-revoke-07");
        JsonNode challenge = challenge(device.deviceId());
        String sessionId = post("/api/attestations", attestRequest(device, challenge, true))
                .getBody().get("sessionId").asText();

        assertEquals(HttpStatus.OK, get("/api/sessions/" + sessionId).getStatusCode());

        var revoke = post("/api/policy/revoke",
                body("deviceId", device.deviceId(), "note", "test revocation"));
        assertEquals(HttpStatus.OK, revoke.getStatusCode());
        long revokeVersion = revoke.getBody().get("version").asLong();

        var check = get("/api/sessions/" + sessionId);
        assertEquals(HttpStatus.UNAUTHORIZED, check.getStatusCode());
        assertEquals("SESSION_REVOKED", check.getBody().get("code").asText());

        JsonNode secondChallenge = challenge(device.deviceId());
        var secondAttest = post("/api/attestations",
                attestRequest(device, secondChallenge, true));
        assertEquals(HttpStatus.UNAUTHORIZED, secondAttest.getStatusCode());
        assertEquals("DEVICE_REVOKED", secondAttest.getBody().get("code").asText());
        assertEquals(revokeVersion,
                secondAttest.getBody().get("evidence").get("decisionPolicyVersion").asLong());

        post("/api/policy/unrevoke", body("deviceId", device.deviceId()));
    }

    @Test
    @DisplayName("证明-08: 不存在的挑战被拒（CHALLENGE_NOT_FOUND）")
    void unknownChallengeRejected() {
        SimulatedDevice device = enrolledDevice("att-noch-08");
        var response = post("/api/attestations", body(
                "challengeId", "ch_does_not_exist",
                "deviceId", device.deviceId(),
                "measurement", device.firmwareMeasurement(),
                "signature", Signatures.toBase64(new byte[]{1, 2, 3})));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("CHALLENGE_NOT_FOUND", response.getBody().get("code").asText());
    }
}
