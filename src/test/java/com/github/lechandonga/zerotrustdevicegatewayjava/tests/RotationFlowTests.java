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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@BusinessDomain("密钥轮换、宽限过渡期与吊销")
class RotationFlowTests extends ApiTestBase {

    private static final String TRUSTED_MEASUREMENT =
            "a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff00";

    private SimulatedDevice enrolledDevice(String id) {
        SimulatedDevice device = new SimulatedDevice(id, TRUSTED_MEASUREMENT);
        String token = "TOKEN-ROT-" + id;
        issueToken(token, id);
        enroll(device, token);
        return device;
    }

    private JsonNode rotateOverHttp(SimulatedDevice device, String gracePeriod) {
        JsonNode challenge = challenge(device.deviceId());
        device.rotateKey();
        byte[] payload = SigningPayloads.rotation(
                device.deviceId(), challenge.get("nonce").asText(),
                device.activePublic().keyId());
        byte[] signature = device.signWithPrevious(payload);
        return post("/api/devices/" + device.deviceId() + "/keys/rotate", body(
                "challengeId", challenge.get("challengeId").asText(),
                "deviceId", device.deviceId(),
                "newKeyAlgorithm", device.activePublic().algorithm(),
                "newPublicKeySpki", Signatures.toBase64(device.activePublic().spki()),
                "signature", Signatures.toBase64(signature),
                "gracePeriod", gracePeriod)).getBody();
    }

    @Test
    @DisplayName("轮换-01: 旧私钥授权轮换成功，服务端同时保存新旧公钥与宽限截止时间")
    void rotateSucceedsWithinTransition() {
        SimulatedDevice device = enrolledDevice("rot-ok-01");

        JsonNode result = rotateOverHttp(device, "PT1H");

        assertEquals(device.activePublic().keyId(), result.get("activeKeyId").asText());
        assertEquals(device.previousPublic().keyId(), result.get("previousKeyId").asText());
        assertNotNull(result.get("graceUntil"));
    }

    @Test
    @DisplayName("轮换-02: 宽限期内旧密钥证明成功，证据 keyRole=PREVIOUS")
    void previousKeyAttestAllowedInGracePeriod() {
        SimulatedDevice device = enrolledDevice("rot-grace-02");
        rotateOverHttp(device, "PT1H");

        JsonNode challenge = challenge(device.deviceId());
        var response = post("/api/attestations", attestRequest(device, challenge, false));

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        JsonNode evidence = response.getBody().get("evidence");
        assertEquals("PREVIOUS", evidence.get("keyRole").asText());
        assertEquals(device.previousPublic().keyId(), evidence.get("keyId").asText());
    }

    @Test
    @DisplayName("轮换-03: 宽限期结束后旧密钥证明被拒（ROTATION_GRACE_EXPIRED）")
    void previousKeyRejectedAfterGraceExpiry() {
        SimulatedDevice device = enrolledDevice("rot-expired-03");
        rotateOverHttp(device, "PT0.3S");
        try {
            Thread.sleep(700);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        JsonNode challenge = challenge(device.deviceId());
        var response = post("/api/attestations", attestRequest(device, challenge, false));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("ROTATION_GRACE_EXPIRED", response.getBody().get("code").asText());
    }

    @Test
    @DisplayName("轮换-04: 宽限期内新密钥证明成功（keyRole=ACTIVE），过渡期后旧密钥彻底不可用")
    void activeKeyWorksAndOldKeyDiesAfterFinalize() {
        SimulatedDevice device = enrolledDevice("rot-final-04");
        rotateOverHttp(device, "PT1H");

        JsonNode firstChallenge = challenge(device.deviceId());
        var activeAttest = post("/api/attestations",
                attestRequest(device, firstChallenge, true));
        assertEquals(HttpStatus.CREATED, activeAttest.getStatusCode());
        assertEquals("ACTIVE",
                activeAttest.getBody().get("evidence").get("keyRole").asText());

        var finalized = post("/api/devices/" + device.deviceId() + "/keys/finalize", body());
        assertEquals(HttpStatus.OK, finalized.getStatusCode());
        assertEquals(true, finalized.getBody().get("previousKeyId").isNull());

        JsonNode secondChallenge = challenge(device.deviceId());
        var oldKeyAttempt = post("/api/attestations",
                attestRequest(device, secondChallenge, false));
        assertEquals(HttpStatus.UNAUTHORIZED, oldKeyAttempt.getStatusCode());
        assertEquals("KEY_NOT_BOUND", oldKeyAttempt.getBody().get("code").asText(),
                "固化后服务端已无旧公钥，显式 keyId 不再绑定于设备");

        JsonNode thirdChallenge = challenge(device.deviceId());
        var oldKeyWithoutHint = post("/api/attestations", body(
                "challengeId", thirdChallenge.get("challengeId").asText(),
                "deviceId", device.deviceId(),
                "measurement", device.firmwareMeasurement(),
                "keyId", null,
                "signature", Signatures.toBase64(device.signWithPrevious(
                        SigningPayloads.attestation(device.deviceId(),
                                thirdChallenge.get("nonce").asText(),
                                device.firmwareMeasurement())))));
        assertEquals(HttpStatus.UNAUTHORIZED, oldKeyWithoutHint.getStatusCode());
        assertEquals("INVALID_SIGNATURE", oldKeyWithoutHint.getBody().get("code").asText());
    }

    @Test
    @DisplayName("轮换-05: 轮换请求重放被拒（CHALLENGE_ALREADY_USED）")
    void rotationReplayRejected() {
        SimulatedDevice device = enrolledDevice("rot-replay-05");
        JsonNode challenge = challenge(device.deviceId());
        device.rotateKey();
        byte[] payload = SigningPayloads.rotation(
                device.deviceId(), challenge.get("nonce").asText(),
                device.activePublic().keyId());
        String signature = Signatures.toBase64(device.signWithPrevious(payload));
        Object requestBody = body(
                "challengeId", challenge.get("challengeId").asText(),
                "deviceId", device.deviceId(),
                "newKeyAlgorithm", device.activePublic().algorithm(),
                "newPublicKeySpki", Signatures.toBase64(device.activePublic().spki()),
                "signature", signature,
                "gracePeriod", "PT1H");

        assertEquals(HttpStatus.OK,
                post("/api/devices/" + device.deviceId() + "/keys/rotate", requestBody)
                        .getStatusCode());
        var replay = post("/api/devices/" + device.deviceId() + "/keys/rotate", requestBody);
        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        assertEquals("CHALLENGE_ALREADY_USED", replay.getBody().get("code").asText());
    }

    @Test
    @DisplayName("轮换-06: 被吊销的设备不允许轮换密钥（DEVICE_REVOKED）")
    void revokedDeviceCannotRotate() {
        SimulatedDevice device = enrolledDevice("rot-revoked-06");
        post("/api/policy/revoke", body("deviceId", device.deviceId(), "note", "revoke before rotate"));

        JsonNode challenge = challenge(device.deviceId());
        device.rotateKey();
        byte[] payload = SigningPayloads.rotation(
                device.deviceId(), challenge.get("nonce").asText(),
                device.activePublic().keyId());
        var response = post("/api/devices/" + device.deviceId() + "/keys/rotate", body(
                "challengeId", challenge.get("challengeId").asText(),
                "deviceId", device.deviceId(),
                "newKeyAlgorithm", device.activePublic().algorithm(),
                "newPublicKeySpki", Signatures.toBase64(device.activePublic().spki()),
                "signature", Signatures.toBase64(device.signWithPrevious(payload)),
                "gracePeriod", "PT1H"));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("DEVICE_REVOKED", response.getBody().get("code").asText());

        post("/api/policy/unrevoke", body("deviceId", device.deviceId()));
    }
}
