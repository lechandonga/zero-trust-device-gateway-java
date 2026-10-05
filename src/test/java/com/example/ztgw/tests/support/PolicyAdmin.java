package com.example.ztgw.tests.support;

import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class PolicyAdmin {

    private PolicyAdmin() {
    }

    public static long publish(TestRestTemplate rest, Set<String> baselines,
                               Set<String> revoked, String reason) {
        ResponseEntity<Map> response = rest.postForEntity("/api/admin/policy", Map.of(
                "trustedMeasurements", baselines,
                "revokedDevices", revoked,
                "reason", reason), Map.class);
        assertEquals(200, response.getStatusCode().value(),
                "policy publish should succeed: " + response.getBody());
        return ((Number) response.getBody().get("version")).longValue();
    }

    public static long currentVersion(TestRestTemplate rest) {
        ResponseEntity<Map> response = rest.getForEntity("/api/admin/policy/current", Map.class);
        return ((Number) response.getBody().get("version")).longValue();
    }
}
