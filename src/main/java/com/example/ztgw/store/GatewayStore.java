package com.example.ztgw.store;

import com.example.ztgw.model.Challenge;
import com.example.ztgw.model.DecisionRecord;
import com.example.ztgw.model.DeviceIdentity;
import com.example.ztgw.model.EnrollmentToken;
import com.example.ztgw.model.PolicySnapshot;
import com.example.ztgw.model.Session;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class GatewayStore {

    private final Map<String, EnrollmentToken> tokens = new ConcurrentHashMap<>();
    private final Map<String, DeviceIdentity> devices = new ConcurrentHashMap<>();
    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Deque<DecisionRecord> decisions = new ArrayDeque<>();

    private static final int MAX_DECISIONS = 1000;

    public Map<String, EnrollmentToken> tokens() {
        return tokens;
    }

    public Map<String, DeviceIdentity> devices() {
        return devices;
    }

    public Map<String, Challenge> challenges() {
        return challenges;
    }

    public Map<String, Session> sessions() {
        return sessions;
    }

    public Optional<DeviceIdentity> findDevice(String deviceId) {
        return Optional.ofNullable(devices.get(deviceId));
    }

    public DeviceIdentity getDevice(String deviceId) {
        return devices.get(deviceId);
    }

    public Optional<Challenge> findChallenge(String challengeId) {
        return Optional.ofNullable(challenges.get(challengeId));
    }

    public Optional<Session> findSession(String sessionToken) {
        return Optional.ofNullable(sessions.get(sessionToken));
    }

    public void addDecision(DecisionRecord record) {
        synchronized (decisions) {
            decisions.addLast(record);
            while (decisions.size() > MAX_DECISIONS) {
                decisions.removeFirst();
            }
        }
    }

    public List<DecisionRecord> recentDecisions(int limit) {
        synchronized (decisions) {
            int size = Math.min(limit, decisions.size());
            List<DecisionRecord> tail = new ArrayList<>(size);
            var iterator = decisions.descendingIterator();
            for (int i = 0; i < size && iterator.hasNext(); i++) {
                tail.add(iterator.next());
            }
            return tail;
        }
    }
}
