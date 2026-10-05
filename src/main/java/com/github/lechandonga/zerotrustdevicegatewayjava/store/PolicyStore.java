package com.github.lechandonga.zerotrustdevicegatewayjava.store;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.PolicySnapshot;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 带版本的策略存储。
 *
 * <p>当前策略通过 AtomicReference 发布不可变快照，并发请求要么看到旧版、
 * 要么看到新版，绝不会看到“半更新”的混合规则；每次发布版本号严格 +1。
 * 历史版本全部保留，准入证据可回指其依据的具体版本。
 */
@Component
public class PolicyStore {

    private final Clock clock;
    private final ConcurrentMap<Long, PolicySnapshot> history = new ConcurrentHashMap<>();
    private final AtomicReference<PolicySnapshot> current =
            new AtomicReference<>(initial());

    public PolicyStore(Clock clock) {
        this.clock = clock;
        history.put(current.get().version(), current.get());
    }

    private static PolicySnapshot initial() {
        return new PolicySnapshot(1L, Instant.EPOCH, Set.of(), Set.of(), "initial empty policy");
    }

    public PolicySnapshot current() {
        return current.get();
    }

    public PolicySnapshot getVersion(long version) {
        return history.get(version);
    }

    /** 发布全量替换式新版本。 */
    public synchronized PolicySnapshot publish(Set<String> trustedMeasurements,
                                               Set<String> revokedDevices,
                                               String note) {
        long nextVersion = current.get().version() + 1;
        PolicySnapshot snapshot = new PolicySnapshot(
                nextVersion,
                Instant.now(clock),
                Collections.unmodifiableSet(Set.copyOf(trustedMeasurements)),
                Collections.unmodifiableSet(Set.copyOf(revokedDevices)),
                note == null ? "" : note);
        history.put(nextVersion, snapshot);
        current.set(snapshot);
        return snapshot;
    }

    /** 在当前版本基础上增量调整（增删度量/吊销项），生成新版本。 */
    public synchronized PolicySnapshot amend(Set<String> addMeasurements,
                                             Set<String> removeMeasurements,
                                             Set<String> addRevocations,
                                             Set<String> removeRevocations,
                                             String note) {
        PolicySnapshot base = current.get();
        Set<String> measurements = new java.util.LinkedHashSet<>(base.trustedMeasurements());
        measurements.addAll(addMeasurements);
        measurements.removeAll(removeMeasurements);
        Set<String> revoked = new java.util.LinkedHashSet<>(base.revokedDevices());
        revoked.addAll(addRevocations);
        revoked.removeAll(removeRevocations);
        return publish(measurements, revoked, note);
    }

    public Map<Long, PolicySnapshot> history() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(history));
    }
}
