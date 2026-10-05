package com.github.lechandonga.zerotrustdevicegatewayjava.store;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.EnrollmentToken;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 入网令牌存储。
 */
@Component
public class TokenStore {

    private final ConcurrentMap<String, EnrollmentToken> tokens = new ConcurrentHashMap<>();

    public EnrollmentToken put(EnrollmentToken token) {
        tokens.put(token.value(), token);
        return token;
    }

    public Optional<EnrollmentToken> find(String value) {
        return Optional.ofNullable(tokens.get(value));
    }
}
