package com.example.ztgw.tests.support;

import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Simulates a physical device using a locally generated Ed25519 key pair:
 * it can enroll, answer attestation challenges and perform signed key
 * rotation. No real hardware or external credential is involved.
 */
public class SimulatedDevice {

    private final TestRestTemplate rest;
    private final String deviceId;
    private KeyPair keyPair;
    private String firmwareMeasurement;

    public SimulatedDevice(TestRestTemplate rest, String deviceId, String firmwareMeasurement) {
        this.rest = rest;
        this.deviceId = deviceId;
        this.firmwareMeasurement = firmwareMeasurement;
        try {
            this.keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getPublicKeyB64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String getFingerprint() {
        return com.example.ztgw.crypto.KeyIds
                .fingerprint(keyPair.getPublic());
    }

    public String getFirmwareMeasurement() {
        return firmwareMeasurement;
    }

    public void setFirmwareMeasurement(String firmwareMeasurement) {
        this.firmwareMeasurement = firmwareMeasurement;
    }

    public String issueToken() {
        ResponseEntity<Map> response = rest.postForEntity("/api/admin/tokens",
                Map.of("deviceId", deviceId), Map.class);
        assertEquals(200, response.getStatusCode().value());
        return (String) response.getBody().get("token");
    }

    public ResponseEntity<Map> enrollRaw(String token) {
        return rest.postForEntity("/api/devices/enroll", Map.of(
                "deviceId", deviceId,
                "token", token,
                "publicKey", getPublicKeyB64()), Map.class);
    }

    public void enroll() {
        ResponseEntity<Map> response = enrollRaw(issueToken());
        assertEquals(200, response.getStatusCode().value(),
                "enrollment should succeed: " + response.getBody());
    }

    public Map<String, Object> challenge(String purpose) {
        ResponseEntity<Map> response = rest.postForEntity("/api/devices/challenges",
                Map.of("deviceId", deviceId, "purpose", purpose), Map.class);
        assertEquals(200, response.getStatusCode().value());
        return response.getBody();
    }

    public Map<String, Object> attestChallenge(Map<String, Object> challenge) {
        return attestChallenge(challenge, firmwareMeasurement, keyPair);
    }

    public Map<String, Object> attestChallenge(Map<String, Object> challenge,
                                               String measurement, KeyPair signer) {
        String challengeId = (String) challenge.get("challengeId");
        String nonce = (String) challenge.get("nonce");
        String payload = com.example.ztgw.crypto.Signatures
                .attestPayload(challengeId, nonce, measurement);
        String signature = com.example.ztgw.crypto.Signatures
                .sign(signer.getPrivate(), payload);
        return Map.of(
                "challengeId", challengeId,
                "deviceId", deviceId,
                "measurement", measurement,
                "publicKey", Base64.getEncoder().encodeToString(signer.getPublic().getEncoded()),
                "signature", signature);
    }

    public ResponseEntity<Map> attestRaw(Map<String, Object> challenge) {
        return rest.postForEntity("/api/devices/attest", attestChallenge(challenge), Map.class);
    }

    public String attestAndGetSession() {
        Map<String, Object> challenge = challenge("ATTEST");
        ResponseEntity<Map> response = attestRaw(challenge);
        assertEquals(200, response.getStatusCode().value(),
                "attestation should succeed: " + response.getBody());
        return (String) response.getBody().get("sessionToken");
    }

    public ResponseEntity<Map> verifySessionRaw(String sessionToken) {
        return rest.postForEntity("/api/devices/sessions/verify",
                Map.of("sessionToken", sessionToken), Map.class);
    }

    public void rotateKey(KeyPair newPair) {
        Map<String, Object> challenge = challenge("ROTATE");
        String newPublicB64 = Base64.getEncoder().encodeToString(newPair.getPublic().getEncoded());
        String oldFingerprint = getFingerprint();
        String newFingerprint = com.example.ztgw.crypto.KeyIds
                .fingerprint(newPair.getPublic());
        String payload = com.example.ztgw.crypto.Signatures
                .rotationPayload((String) challenge.get("challengeId"),
                        (String) challenge.get("nonce"), oldFingerprint, newFingerprint);
        String signature = com.example.ztgw.crypto.Signatures
                .sign(keyPair.getPrivate(), payload);
        ResponseEntity<Map> response = rest.postForEntity("/api/devices/keys/rotate", Map.of(
                "challengeId", challenge.get("challengeId"),
                "deviceId", deviceId,
                "oldPublicKey", getPublicKeyB64(),
                "newPublicKey", newPublicB64,
                "signature", signature), Map.class);
        assertEquals(200, response.getStatusCode().value(),
                "key rotation should succeed: " + response.getBody());
        this.keyPair = newPair;
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void useKeyPair(KeyPair pair) {
        this.keyPair = pair;
    }

    public ResponseEntity<Map> attestWithRawSigner(Map<String, Object> challenge, KeyPair signer) {
        return rest.exchange("/api/devices/attest",
                org.springframework.http.HttpMethod.POST,
                new HttpEntity<>(attestChallenge(challenge, firmwareMeasurement, signer)), Map.class);
    }
}
