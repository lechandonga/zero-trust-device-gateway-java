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

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessDomain("策略版本语义与并发一致性")
class PolicyVersionTests extends ApiTestBase {

    private static final String TRUSTED_MEASUREMENT =
            "a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff00";
    private static final String NEW_MEASUREMENT =
            "00ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211";

    private SimulatedDevice enrolledDevice(String id) {
        post("/api/policy/publish", body(
                "trustedMeasurements", List.of(TRUSTED_MEASUREMENT),
                "revokedDevices", List.of(),
                "note", "ensure trusted baseline before test"));
        SimulatedDevice device = new SimulatedDevice(id, TRUSTED_MEASUREMENT);
        String token = "TOKEN-POL-" + id;
        issueToken(token, id);
        enroll(device, token);
        return device;
    }

    @Test
    @DisplayName("策略-01: 基线变更只影响新版本，旧版本不被静默改写")
    void policyVersionsAreImmutable() {
        long before = get("/api/policy/current").getBody().get("version").asLong();

        var published = post("/api/policy/publish", body(
                "trustedMeasurements", List.of(NEW_MEASUREMENT),
                "revokedDevices", List.of(),
                "note", "baseline rotated"));

        assertEquals(HttpStatus.OK, published.getStatusCode());
        assertEquals(before + 1, published.getBody().get("version").asLong());

        JsonNode oldVersion = get("/api/policy/versions/" + before).getBody();
        assertTrue(oldVersion.get("trustedMeasurements").toString().contains(TRUSTED_MEASUREMENT),
                "历史版本仍保留旧基线");
    }

    @Test
    @DisplayName("策略-02: 挑战钉住发放时策略版本，证明按钉住版本判定，不被中途发布的新版本影响")
    void challengePinnedPolicyVersionSurvivesSwitch() {
        SimulatedDevice device = enrolledDevice("pol-pin-02");
        JsonNode challenge = challenge(device.deviceId());
        long pinnedVersion = challenge.get("policyVersion").asLong();

        post("/api/policy/publish", body(
                "trustedMeasurements", List.of(NEW_MEASUREMENT),
                "revokedDevices", List.of(),
                "note", "baseline changed after challenge issuance"));
        long switchedVersion = get("/api/policy/current").getBody().get("version").asLong();

        var response = post("/api/attestations", attestRequest(device, challenge, true));

        assertEquals(HttpStatus.CREATED, response.getStatusCode(),
                "设备度量仍匹配挑战钉住的旧版基线，应允许准入");
        JsonNode evidence = response.getBody().get("evidence");
        assertEquals(pinnedVersion, evidence.get("challengePolicyVersion").asLong());
        assertEquals(pinnedVersion, evidence.get("decisionPolicyVersion").asLong());

        JsonNode newChallenge = challenge(device.deviceId());
        assertEquals(switchedVersion, newChallenge.get("policyVersion").asLong());
        var underNewPolicy = post("/api/attestations",
                attestRequest(device, newChallenge, true));
        assertEquals(HttpStatus.UNAUTHORIZED, underNewPolicy.getStatusCode());
        assertEquals("MEASUREMENT_UNTRUSTED", underNewPolicy.getBody().get("code").asText());

    }

    @Test
    @DisplayName("策略-03: 吊销发布新版本后历史版本仍显示未吊销，准入证据可回溯具体版本")
    void revocationCreatesVersionButHistoryStaysIntact() {
        SimulatedDevice device = enrolledDevice("pol-rev-03");
        long before = get("/api/policy/current").getBody().get("version").asLong();

        var revoke = post("/api/policy/revoke",
                body("deviceId", device.deviceId(), "note", "versioned revocation"));
        long revokeVersion = revoke.getBody().get("version").asLong();
        assertEquals(before + 1, revokeVersion);
        assertTrue(revoke.getBody().get("revokedDevices").toString().contains(device.deviceId()));

        JsonNode oldVersion = get("/api/policy/versions/" + before).getBody();
        assertEquals(false, oldVersion.get("revokedDevices").toString().contains(device.deviceId()));

        JsonNode history = get("/api/policy/versions").getBody();
        assertTrue(history.get("versions").size() >= (int) revokeVersion);

        post("/api/policy/unrevoke", body("deviceId", device.deviceId()));
    }

    @Test
    @DisplayName("策略-04: 会话证据不可变，策略后续吊销不改变既有证据中的版本与结论")
    void issuedDecisionEvidenceIsImmutable() {
        SimulatedDevice device = enrolledDevice("pol-imm-04");
        JsonNode challenge = challenge(device.deviceId());
        JsonNode session = post("/api/attestations",
                attestRequest(device, challenge, true)).getBody();
        long evidenceVersion = session.get("evidence").get("decisionPolicyVersion").asLong();

        post("/api/policy/revoke", body("deviceId", device.deviceId(), "note", "later revocation"));

        var check = get("/api/sessions/" + session.get("sessionId").asText());
        assertEquals(HttpStatus.UNAUTHORIZED, check.getStatusCode());
        assertEquals("SESSION_REVOKED", check.getBody().get("code").asText());

        assertEquals(evidenceVersion, session.get("evidence").get("decisionPolicyVersion").asLong());
        assertEquals(true, session.get("evidence").get("baselineMatched").asBoolean());

        post("/api/policy/unrevoke", body("deviceId", device.deviceId()));
    }
}
