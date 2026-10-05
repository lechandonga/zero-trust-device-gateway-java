package com.example.ztgw.tests;

import com.example.ztgw.support.TimeService;
import com.example.ztgw.tests.support.BusinessCaseLogger;
import com.example.ztgw.tests.support.SimulatedDevice;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(BusinessCaseLogger.class)
class EnrollmentTests {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private TimeService clock;

    @Test
    void firstEnrollmentBindsIdentityOnce() {
        SimulatedDevice device = new SimulatedDevice(rest, "dev-enroll-ok", "fw-1.0");
        ResponseEntity<Map> response = device.enrollRaw(device.issueToken());
        assertEquals(200, response.getStatusCode().value());
        assertEquals(device.getFingerprint(), response.getBody().get("keyFingerprint"));
        assertEquals("ENROLLED", response.getBody().get("status"));
    }

    @Test
    void unknownTokenRejected() {
        SimulatedDevice device = new SimulatedDevice(rest, "dev-enroll-unknown", "fw-1.0");
        ResponseEntity<Map> response = device.enrollRaw("tok_does_not_exist");
        assertEquals(404, response.getStatusCode().value());
        assertEquals("TOKEN_UNKNOWN", response.getBody().get("code"));
    }

    @Test
    void tokenCanBeConsumedOnlyOnce() {
        SimulatedDevice device = new SimulatedDevice(rest, "dev-enroll-once", "fw-1.0");
        String token = device.issueToken();
        assertEquals(200, device.enrollRaw(token).getStatusCode().value());
        ResponseEntity<Map> second = device.enrollRaw(token);
        assertEquals(409, second.getStatusCode().value());
        assertEquals("TOKEN_ALREADY_USED", second.getBody().get("code"));
    }

    @Test
    void expiredTokenRejected() {
        SimulatedDevice device = new SimulatedDevice(rest, "dev-enroll-expired", "fw-1.0");
        String token = device.issueToken();
        clock.advance(Duration.ofSeconds(11));
        ResponseEntity<Map> response = device.enrollRaw(token);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("TOKEN_EXPIRED", response.getBody().get("code"));
    }

    @Test
    void tokenBoundToOtherDeviceRejected() {
        SimulatedDevice device = new SimulatedDevice(rest, "dev-enroll-bound-a", "fw-1.0");
        String token = device.issueToken();
        SimulatedDevice other = new SimulatedDevice(rest, "dev-enroll-bound-b", "fw-1.0");
        ResponseEntity<Map> response = other.enrollRaw(token);
        assertEquals(403, response.getStatusCode().value());
        assertEquals("TOKEN_DEVICE_MISMATCH", response.getBody().get("code"));
    }

    @Test
    void repeatedEnrollmentDoesNotOverwriteBoundKey() {
        SimulatedDevice device = new SimulatedDevice(rest, "dev-enroll-repeat", "fw-1.0");
        device.enroll();
        String originalFingerprint = device.getFingerprint();
        device.useKeyPair(SimulatedDevice.generateKeyPair());
        assertNotEquals(originalFingerprint, device.getFingerprint());

        ResponseEntity<Map> response = device.enrollRaw(device.issueToken());
        assertEquals(409, response.getStatusCode().value());
        assertEquals("DEVICE_ALREADY_ENROLLED", response.getBody().get("code"));

        ResponseEntity<Map> view = rest.getForEntity(
                "/api/admin/devices/dev-enroll-repeat", Map.class);
        assertEquals(originalFingerprint,
                ((Map<?, ?>) view.getBody().get("currentKey")).get("fingerprint"));
    }
}
