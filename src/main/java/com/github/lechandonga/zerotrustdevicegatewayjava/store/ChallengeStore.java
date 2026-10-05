package com.github.lechandonga.zerotrustdevicegatewayjava.store;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.Challenge;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 挑战存储。
 */
@Component
public class ChallengeStore {

    private final ConcurrentMap<String, Challenge> challenges = new ConcurrentHashMap<>();

    public Challenge put(Challenge challenge) {
        challenges.put(challenge.challengeId(), challenge);
        return challenge;
    }

    public Optional<Challenge> find(String challengeId) {
        return Optional.ofNullable(challenges.get(challengeId));
    }
}
