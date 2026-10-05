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

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(BusinessCaseLogger.class)
class RevocationTests {

    private static final String FW = "sha256:fw-rev-1";

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private TimeService clock;

    private SimulatedDevice device;

    @BeforeEach
    void setUp() {
        device = new SimulatedDevice(rest, "dev-rev-" + System.nanoTime(), FW);
        device.enroll();
        PolicyAdmin.publish(rest, Set.of(FW), Set.of(), "baseline for revocation suite");
    }

    @Test
    void revokingDeviceInvalidatesExistingSessionImmediately() {
        String session = device.attestAndGetSession();
        assertEquals(200, device.verifySessionRaw(session).getStatusCode().value());

        long version = PolicyAdmin.publish(rest, Set.of(FW),
                Set.of(device.getDeviceId()), "device compromised -> revoke");

        ResponseEntity<Map> verify = device.verifySessionRaw(session);
        assertEquals(403, verify.getStatusCode().value());
        assertEquals("SESSION_DEVICE_REVOKED", verify.getBody().get("code"));

        ResponseEntity<Map> newProof = device.attestRaw(device.challenge("ATTEST"));
        assertEquals(403, newProof.getStatusCode().value());
        assertEquals("DEVICE_REVOKED", newProof.getBody().get("code"));

        ResponseEntity<Map> view = rest.getForEntity(
                "/api/admin/devices/" + device.getDeviceId(), Map.class);
        assertEquals(true, view.getBody().get("revoked"));
        assertEquals(version, ((Number) view.getBody().get("evaluatedPolicyVersion")).longValue());
    }

    @Test
    void revokedDeviceCannotRotateKeys() {
        PolicyAdmin.publish(rest, Set.of(FW), Set.of(device.getDeviceId()), "revoke before rotation");
        java.security.KeyPair newPair = SimulatedDevice.generateKeyPair();
        Map<String, Object> challenge = device.challenge("ROTATE");
        String oldFp = device.getFingerprint();
        String newFp = com.example.ztgw.crypto.KeyIds
                .fingerprint(newPair.getPublic());
        String payload = com.example.ztgw.crypto.Signatures
                .rotationPayload((String) challenge.get("challengeId"),
                        (String) challenge.get("nonce"), oldFp, newFp);
        String signature = com.example.ztgw.crypto.Signatures
                .sign(device.getKeyPair().getPrivate(), payload);
        ResponseEntity<Map> response = rest.postForEntity("/api/devices/keys/rotate", Map.of(
                "challengeId", challenge.get("challengeId"),
                "deviceId", device.getDeviceId(),
                "oldPublicKey", device.getPublicKeyB64(),
                "newPublicKey", java.util.Base64.getEncoder()
                        .encodeToString(newPair.getPublic().getEncoded()),
                "signature", signature), Map.class);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("DEVICE_REVOKED", response.getBody().get("code"));
    }

    @Test
    void unrevokingDeviceRestoresAccessAtNewVersion() {
        PolicyAdmin.publish(rest, Set.of(FW), Set.of(device.getDeviceId()), "temporary revoke");
        assertEquals(403, device.attestRaw(device.challenge("ATTEST")).getStatusCode().value());

        long restoredVersion = PolicyAdmin.publish(rest, Set.of(FW), Set.of(),
                "incident resolved -> remove revocation");
        String session = device.attestAndGetSession();
        ResponseEntity<Map> verify = device.verifySessionRaw(session);
        assertEquals(200, verify.getStatusCode().value());
        assertEquals(restoredVersion, ((Number) verify.getBody().get("evaluatedPolicyVersion")).longValue());
    }
}
