package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.PolicySnapshot;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.PolicyStore;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

/**
 * 受信基线与吊销名单的版本化管理。
 */
@Service
public class PolicyService {

    private final PolicyStore policyStore;

    public PolicyService(PolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    public PolicySnapshot current() {
        return policyStore.current();
    }

    public PolicySnapshot version(long version) {
        PolicySnapshot snapshot = policyStore.getVersion(version);
        if (snapshot == null) {
            throw com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException
                    .notFound("POLICY_VERSION_NOT_FOUND", "unknown policy version: " + version);
        }
        return snapshot;
    }

    public Map<Long, PolicySnapshot> history() {
        return policyStore.history();
    }

    public PolicySnapshot publish(Set<String> trustedMeasurements, Set<String> revokedDevices,
                                  String note) {
        return policyStore.publish(trustedMeasurements, revokedDevices, note);
    }

    public PolicySnapshot revoke(String deviceId, String note) {
        return policyStore.amend(Set.of(), Set.of(), Set.of(deviceId), Set.of(),
                note != null ? note : "revoke " + deviceId);
    }

    public PolicySnapshot unrevoke(String deviceId, String note) {
        return policyStore.amend(Set.of(), Set.of(), Set.of(), Set.of(deviceId),
                note != null ? note : "unrevoke " + deviceId);
    }
}
