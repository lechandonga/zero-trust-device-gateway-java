package com.example.ztgw.model;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public record DecisionRecord(String decisionId,
                             String kind,
                             String deviceId,
                             boolean allow,
                             long policyVersion,
                             String challengeId,
                             String keyFingerprint,
                             String measurement,
                             String reason,
                             Instant at) {

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("decisionId", decisionId);
        map.put("kind", kind);
        map.put("deviceId", deviceId);
        map.put("allow", allow);
        map.put("policyVersion", policyVersion);
        map.put("challengeId", challengeId);
        map.put("keyFingerprint", keyFingerprint);
        map.put("measurement", measurement);
        map.put("reason", reason);
        map.put("at", at);
        return map;
    }
}
