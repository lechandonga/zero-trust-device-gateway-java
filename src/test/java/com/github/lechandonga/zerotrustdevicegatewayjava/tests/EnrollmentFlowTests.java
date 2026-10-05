package com.github.lechandonga.zerotrustdevicegatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.zerotrustdevicegatewayjava.crypto.Signatures;
import com.github.lechandonga.zerotrustdevicegatewayjava.device.SimulatedDevice;
import com.github.lechandonga.zerotrustdevicegatewayjava.tests.support.ApiTestBase;
import com.github.lechandonga.zerotrustdevicegatewayjava.tests.support.BusinessDomain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@BusinessDomain("设备首次入网与身份绑定")
class EnrollmentFlowTests extends ApiTestBase {

    private SimulatedDevice newDevice(String id) {
        return new SimulatedDevice(id, "firmware-" + id);
    }

    @Test
    @DisplayName("入网-01: 合法一次性令牌登记成功并返回绑定公钥指纹")
    void enrollWithValidToken() {
        SimulatedDevice device = newDevice("enroll-success-01");
        issueToken("TOKEN-ENROLL-01", device.deviceId());

        JsonNode response = enroll(device, "TOKEN-ENROLL-01").getBody();

        assertNotNull(response);
        assertEquals(device.deviceId(), response.get("deviceId").asText());
        assertEquals(device.activePublic().keyId(), response.get("activeKeyId").asText());
    }

    @Test
    @DisplayName("入网-02: 同一令牌重复使用第二次被拒（TOKEN_ALREADY_USED）")
    void reusedTokenRejected() {
        SimulatedDevice first = new SimulatedDevice("enroll-reused-a", "firmware-a");
        SimulatedDevice second = new SimulatedDevice("enroll-reused-b", "firmware-b");
        issueToken("TOKEN-ENROLL-02", null);

        assertEquals(HttpStatus.CREATED, enroll(first, "TOKEN-ENROLL-02").getStatusCode());
        var replay = post("/api/enrollment/enroll", body(
                "token", "TOKEN-ENROLL-02",
                "deviceId", second.deviceId(),
                "keyAlgorithm", second.activePublic().algorithm(),
                "publicKeySpki", Signatures.toBase64(second.activePublic().spki())));

        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        assertEquals("TOKEN_ALREADY_USED", replay.getBody().get("code").asText());
    }

    @Test
    @DisplayName("入网-03: 过期令牌被拒（TOKEN_EXPIRED）")
    void expiredTokenRejected() throws Exception {
        SimulatedDevice device = newDevice("enroll-expired-03");
        post("/api/enrollment/tokens",
                body("token", "TOKEN-ENROLL-03", "expectedDeviceId", device.deviceId(),
                        "ttl", "PT0.2S"));
        Thread.sleep(600);

        var response = enroll(device, "TOKEN-ENROLL-03");

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("TOKEN_EXPIRED", response.getBody().get("code").asText());
    }

    @Test
    @DisplayName("入网-04: 不存在的令牌被拒（TOKEN_MISMATCH）")
    void unknownTokenRejected() {
        SimulatedDevice device = newDevice("enroll-unknown-04");

        var response = enroll(device, "NO-SUCH-TOKEN");

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("TOKEN_MISMATCH", response.getBody().get("code").asText());
    }

    @Test
    @DisplayName("入网-05: 令牌绑定的设备不匹配被拒（TOKEN_DEVICE_MISMATCH），且令牌未被消费")
    void tokenBoundToOtherDeviceRejected() {
        SimulatedDevice device = newDevice("enroll-bound-05");
        issueToken("TOKEN-ENROLL-05", "a-different-device");

        var mismatch = enroll(device, "TOKEN-ENROLL-05");
        assertEquals(HttpStatus.UNAUTHORIZED, mismatch.getStatusCode());
        assertEquals("TOKEN_DEVICE_MISMATCH", mismatch.getBody().get("code").asText());

        var bound = post("/api/enrollment/enroll", body(
                "token", "TOKEN-ENROLL-05",
                "deviceId", "a-different-device",
                "keyAlgorithm", device.activePublic().algorithm(),
                "publicKeySpki", Signatures.toBase64(device.activePublic().spki())));
        assertEquals(HttpStatus.CREATED, bound.getStatusCode());
    }

    @Test
    @DisplayName("入网-06: 同一设备重复登记被拒，已有身份与公钥不被覆盖（DEVICE_ALREADY_ENROLLED）")
    void duplicateDeviceDoesNotOverwrite() {
        SimulatedDevice device = newDevice("enroll-dup-06");
        issueToken("TOKEN-ENROLL-06A", device.deviceId());
        issueToken("TOKEN-ENROLL-06B", device.deviceId());

        JsonNode first = enroll(device, "TOKEN-ENROLL-06A").getBody();
        SimulatedDevice anotherKeyMaterial = new SimulatedDevice(device.deviceId(), "firmware-x");
        var duplicate = post("/api/enrollment/enroll", body(
                "token", "TOKEN-ENROLL-06B",
                "deviceId", device.deviceId(),
                "keyAlgorithm", anotherKeyMaterial.activePublic().algorithm(),
                "publicKeySpki", Signatures.toBase64(anotherKeyMaterial.activePublic().spki())));

        assertEquals(HttpStatus.CONFLICT, duplicate.getStatusCode());
        assertEquals("DEVICE_ALREADY_ENROLLED", duplicate.getBody().get("code").asText());
        assertEquals(first.get("activeKeyId").asText(),
                device.activePublic().keyId());
    }

}
