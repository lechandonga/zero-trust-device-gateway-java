package com.example.ztgw.service;

import com.example.ztgw.error.ApiException;
import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.store.PolicyStore;
import com.example.ztgw.support.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class PolicyService {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

    private final PolicyStore policyStore;
    private final TimeService timeService;

    public PolicyService(PolicyStore policyStore, TimeService timeService) {
        this.policyStore = policyStore;
        this.timeService = timeService;
    }

    public PolicySnapshot current() {
        return policyStore.current();
    }

    public List<PolicySnapshot> history() {
        return policyStore.history();
    }

    /**
     * Publish a fully-specified new immutable version. The caller must send the
     * complete desired baseline and revocation set; no silent merge happens.
     * {@code expectedVersion} is an optimistic-concurrency check.
     */
    public synchronized PolicySnapshot publish(Long expectedVersion, Set<String> trustedMeasurements,
                                               Set<String> revokedDevices, String reason) {
        PolicySnapshot current = policyStore.current();
        if (expectedVersion != null && expectedVersion != current.version()) {
            throw ApiException.preconditionFailed("POLICY_VERSION_CONFLICT",
                    "policy changed since the client last read it; expected v" + expectedVersion
                            + " but current is v" + current.version());
        }
        Set<String> measurements = trustedMeasurements == null
                ? new LinkedHashSet<>(current.trustedMeasurements())
                : new LinkedHashSet<>(trustedMeasurements);
        Set<String> revocations = revokedDevices == null
                ? new LinkedHashSet<>(current.revokedDevices())
                : new LinkedHashSet<>(revokedDevices);
        PolicySnapshot snapshot = policyStore.publish(measurements, revocations,
                reason == null ? "policy update" : reason, timeService.now());
        log.info("[POLICY] published v{} baselines={} revoked={} reason='{}'",
                snapshot.version(), measurements.size(), revocations.size(), snapshot.reason());
        return snapshot;
    }
}
