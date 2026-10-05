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
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(BusinessCaseLogger.class)
class RotationTests {

    private static final String FW = "sha256:fw-rot-1";

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private TimeService clock;

    private SimulatedDevice device;
    private KeyPair oldPair;

    @BeforeEach
    void setUp() {
        device = new SimulatedDevice(rest, "dev-rot-" + System.nanoTime(), FW);
        device.enroll();
        oldPair = device.getKeyPair();
        PolicyAdmin.publish(rest, Set.of(FW), Set.of(), "baseline for rotation suite");
    }

    @Test
    void bothKeysWorkDuringGraceWindow() {
        KeyPair newPair = SimulatedDevice.generateKeyPair();
        device.rotateKey(newPair);

        assertEquals(200, device.attestWithRawSigner(device.challenge("ATTEST"), newPair)
                .getStatusCode().value(), "new key proves identity immediately");

        clock.advance(Duration.ofSeconds(2));
        assertEquals(200, device.attestWithRawSigner(device.challenge("ATTEST"), oldPair)
                .getStatusCode().value(), "old key still proves inside grace window");

        ResponseEntity<Map> view = rest.getForEntity(
                "/api/admin/devices/" + device.getDeviceId(), Map.class);
        assertEquals("OLD_GRACE", ((Map<?, ?>) view.getBody().get("previousKey")).get("status"));
    }

    @Test
    void oldKeyRejectedAfterGraceWindow() {
        KeyPair newPair = SimulatedDevice.generateKeyPair();
        device.rotateKey(newPair);

        clock.advance(Duration.ofSeconds(6));
        ResponseEntity<Map> oldProof = device.attestWithRawSigner(
                device.challenge("ATTEST"), oldPair);
        assertEquals(403, oldProof.getStatusCode().value());
        assertEquals("OLD_KEY_GRACE_EXPIRED", oldProof.getBody().get("code"));

        assertEquals(200, device.attestWithRawSigner(device.challenge("ATTEST"), newPair)
                .getStatusCode().value(), "new key keeps working after grace ends");
    }

    @Test
    void rotationMustBeSignedByCurrentKey() {
        KeyPair newPair = SimulatedDevice.generateKeyPair();
        device.rotateKey(newPair);
        KeyPair newerPair = SimulatedDevice.generateKeyPair();

        Map<String, Object> challenge = device.challenge("ROTATE");
        String oldFp = com.example.ztgw.crypto.KeyIds
                .fingerprint(oldPair.getPublic());
        String newerFp = com.example.ztgw.crypto.KeyIds
                .fingerprint(newerPair.getPublic());
        String payload = com.example.ztgw.crypto.Signatures
                .rotationPayload((String) challenge.get("challengeId"),
                        (String) challenge.get("nonce"), oldFp, newerFp);
        String signature = com.example.ztgw.crypto.Signatures
                .sign(oldPair.getPrivate(), payload);
        ResponseEntity<Map> response = rest.postForEntity("/api/devices/keys/rotate", Map.of(
                "challengeId", challenge.get("challengeId"),
                "deviceId", device.getDeviceId(),
                "oldPublicKey", java.util.Base64.getEncoder()
                        .encodeToString(oldPair.getPublic().getEncoded()),
                "newPublicKey", java.util.Base64.getEncoder()
                        .encodeToString(newerPair.getPublic().getEncoded()),
                "signature", signature), Map.class);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("ROTATION_SIGNER_NOT_CURRENT", response.getBody().get("code"));
    }

    @Test
    void rotationChallengeIsOneShotAndPurposeBound() {
        KeyPair newPair = SimulatedDevice.generateKeyPair();
        Map<String, Object> rotateChallenge = device.challenge("ROTATE");

        ResponseEntity<Map> asAttest = rest.postForEntity("/api/devices/attest", Map.of(
                "challengeId", rotateChallenge.get("challengeId"),
                "deviceId", device.getDeviceId(),
                "measurement", FW,
                "publicKey", device.getPublicKeyB64(),
                "signature", "AAAA"), Map.class);
        assertEquals(400, asAttest.getStatusCode().value());
        assertEquals("CHALLENGE_PURPOSE_MISMATCH", asAttest.getBody().get("code"));

        device.rotateKey(newPair);
        assertNotEquals(com.example.ztgw.crypto.KeyIds
                .fingerprint(oldPair.getPublic()), device.getFingerprint());
    }
}
