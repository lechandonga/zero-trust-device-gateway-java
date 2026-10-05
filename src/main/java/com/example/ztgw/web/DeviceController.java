package com.example.ztgw.web;

import com.example.ztgw.model.Challenge;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.model.Session;
import com.example.ztgw.service.AttestationService;
import com.example.ztgw.service.ChallengeService;
import com.example.ztgw.service.EnrollmentService;
import com.example.ztgw.service.RotationService;
import com.example.ztgw.store.GatewayStore;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final EnrollmentService enrollmentService;
    private final ChallengeService challengeService;
    private final AttestationService attestationService;
    private final RotationService rotationService;
    private final GatewayStore store;

    public DeviceController(EnrollmentService enrollmentService, ChallengeService challengeService,
                            AttestationService attestationService, RotationService rotationService,
                            GatewayStore store) {
        this.enrollmentService = enrollmentService;
        this.challengeService = challengeService;
        this.attestationService = attestationService;
        this.rotationService = rotationService;
        this.store = store;
    }

    @PostMapping("/enroll")
    public Map<String, Object> enroll(@RequestBody ApiDtos.EnrollRequest request) {
        DeviceIdentity identity = enrollmentService.enroll(
                request.deviceId(), request.token(), request.publicKey());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("deviceId", identity.getDeviceId());
        body.put("keyFingerprint", identity.getCurrentKey().fingerprint());
        body.put("enrolledAt", identity.getEnrolledAt());
        body.put("status", "ENROLLED");
        return body;
    }

    @PostMapping("/challenges")
    public Map<String, Object> challenge(@RequestBody ApiDtos.ChallengeRequest request) {
        String purposeValue = request.purpose() == null ? "ATTEST" : request.purpose().toUpperCase();
        Challenge.Purpose purpose;
        try {
            purpose = Challenge.Purpose.valueOf(purposeValue);
        } catch (IllegalArgumentException e) {
            throw new com.example.ztgw.error.ApiException(
                    "INVALID_PURPOSE", "purpose must be ATTEST or ROTATE",
                    org.springframework.http.HttpStatus.BAD_REQUEST);
        }
        Challenge challenge = challengeService.issue(request.deviceId(), purpose);
        return Map.of(
                "challengeId", challenge.getChallengeId(),
                "nonce", challenge.getNonce(),
                "purpose", challenge.getPurpose().name(),
                "policyVersion", challenge.getPolicyVersion(),
                "issuedAt", challenge.getIssuedAt(),
                "expiresAt", challenge.getExpiresAt());
    }

    @PostMapping("/attest")
    public Map<String, Object> attest(@RequestBody ApiDtos.AttestRequest request) {
        Session session = attestationService.attest(request.challengeId(), request.deviceId(),
                request.measurement(), request.publicKey(), request.signature());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionToken", session.getSessionToken());
        body.put("deviceId", session.getDeviceId());
        body.put("issuedAt", session.getIssuedAt());
        body.put("expiresAt", session.getExpiresAt());
        body.put("policyVersion", session.getPolicyVersion());
        body.put("keyFingerprint", session.getKeyFingerprint());
        body.put("measurement", session.getMeasurement());
        body.put("decisionId", session.getDecisionId());
        return body;
    }

    @PostMapping("/sessions/verify")
    public Map<String, Object> verify(@RequestBody ApiDtos.VerifySessionRequest request) {
        return attestationService.verifySession(request.sessionToken());
    }

    @PostMapping("/keys/rotate")
    public Map<String, Object> rotate(@RequestBody ApiDtos.RotateRequest request) {
        Map<String, Object> body = rotationService.rotate(request.challengeId(), request.deviceId(),
                request.oldPublicKey(), request.newPublicKey(), request.signature());
        return body;
    }
}
