package com.example.ztgw.web;

import com.example.ztgw.model.DecisionRecord;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.model.EnrollmentToken;
import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.service.EnrollmentService;
import com.example.ztgw.service.PolicyService;
import com.example.ztgw.store.GatewayStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Administrative endpoints used both by the local demo operator and by tests:
 * mint one-time enrollment tokens, publish versioned policy, and inspect
 * devices / explainable decisions. No external credentials are required.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final EnrollmentService enrollmentService;
    private final PolicyService policyService;
    private final GatewayStore store;

    public AdminController(EnrollmentService enrollmentService, PolicyService policyService,
                           GatewayStore store) {
        this.enrollmentService = enrollmentService;
        this.policyService = policyService;
        this.store = store;
    }

    @PostMapping("/tokens")
    public Map<String, Object> issueToken(@RequestBody(required = false) ApiDtos.IssueTokenRequest request) {
        String deviceId = request == null ? null : request.deviceId();
        EnrollmentToken token = enrollmentService.issueToken(deviceId);
        return Map.of(
                "token", token.getToken(),
                "boundDeviceId", token.getBoundDeviceId() == null ? "" : token.getBoundDeviceId(),
                "issuedAt", token.getIssuedAt(),
                "expiresAt", token.getExpiresAt());
    }

    @GetMapping("/policy/current")
    public PolicySnapshot currentPolicy() {
        return policyService.current();
    }

    @GetMapping("/policy/history")
    public List<PolicySnapshot> policyHistory() {
        return policyService.history();
    }

    @PostMapping("/policy")
    public PolicySnapshot publishPolicy(@RequestBody ApiDtos.PolicyUpdateRequest request) {
        return policyService.publish(request.expectedVersion(),
                request.trustedMeasurements(), request.revokedDevices(), request.reason());
    }

    @GetMapping("/devices/{deviceId}")
    public Map<String, Object> device(@PathVariable String deviceId) {
        DeviceIdentity identity = store.findDevice(deviceId)
                .orElseThrow(() -> new com.example.ztgw.error.ApiException(
                        "DEVICE_NOT_ENROLLED", "device is not registered",
                        org.springframework.http.HttpStatus.NOT_FOUND));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("deviceId", identity.getDeviceId());
        body.put("enrolledAt", identity.getEnrolledAt());
        body.put("currentKey", identity.getCurrentKey().toMap());
        if (identity.getPreviousKey() != null) {
            body.put("previousKey", identity.getPreviousKey().toMap());
        }
        PolicySnapshot current = policyService.current();
        body.put("revoked", current.isRevoked(deviceId));
        body.put("evaluatedPolicyVersion", current.version());
        return body;
    }

    @GetMapping("/decisions")
    public List<Map<String, Object>> decisions(@RequestParam(defaultValue = "50") int limit) {
        return store.recentDecisions(Math.min(limit, 500)).stream()
                .map(DecisionRecord::toMap)
                .toList();
    }
}
