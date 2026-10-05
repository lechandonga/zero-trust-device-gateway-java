package com.example.ztgw.store;

import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.support.TimeService;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Append-only policy history. Version 0 allows nothing (empty baselines, no
 * revocations); admins publish later immutable snapshots.
 */
@Component
public class PolicyStore {

    private final List<PolicySnapshot> history =
            Collections.synchronizedList(new ArrayList<>());

    public PolicyStore(TimeService timeService) {
        history.add(new PolicySnapshot(0L, Set.of(), Set.of(), timeService.now(), "initial empty policy"));
    }

    public PolicySnapshot current() {
        synchronized (history) {
            return history.get(history.size() - 1);
        }
    }

    public PolicySnapshot version(long version) {
        synchronized (history) {
            for (PolicySnapshot snapshot : history) {
                if (snapshot.version() == version) {
                    return snapshot;
                }
            }
            return null;
        }
    }

    public List<PolicySnapshot> history() {
        synchronized (history) {
            return List.copyOf(history);
        }
    }

    public long nextVersion() {
        return current().version() + 1;
    }

    public PolicySnapshot publish(Set<String> trustedMeasurements, Set<String> revokedDevices,
                                  String reason, Instant createdAt) {
        Set<String> measurements = Collections.unmodifiableSet(new LinkedHashSet<>(trustedMeasurements));
        Set<String> revocations = Collections.unmodifiableSet(new LinkedHashSet<>(revokedDevices));
        synchronized (history) {
            PolicySnapshot snapshot = new PolicySnapshot(
                    current().version() + 1, measurements, revocations, createdAt, reason);
            history.add(snapshot);
            return snapshot;
        }
    }
}
