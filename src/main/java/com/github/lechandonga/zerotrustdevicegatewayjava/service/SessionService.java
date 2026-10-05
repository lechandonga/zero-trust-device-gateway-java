package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionSession;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.PolicyStore;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.SessionStore;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

/**
 * 准入会话校验。会话发放时的证据不可变；是否仍有效按实时策略判定，
 * 因此设备被吊销后，已发放会话立即失效，无需改写任何历史判定。
 */
@Service
public class SessionService {

    private final Clock clock;
    private final SessionStore sessionStore;
    private final PolicyStore policyStore;

    public SessionService(Clock clock, SessionStore sessionStore, PolicyStore policyStore) {
        this.clock = clock;
        this.sessionStore = sessionStore;
        this.policyStore = policyStore;
    }

    public AdmissionSession requireValid(String sessionId) {
        AdmissionSession session = sessionStore.find(sessionId)
                .orElseThrow(() -> GatewayException.unauthorized("SESSION_NOT_FOUND",
                        "session does not exist: " + sessionId));
        Instant now = Instant.now(clock);
        if (now.isAfter(session.expiresAt())) {
            throw GatewayException.unauthorized("SESSION_EXPIRED",
                    "session expired at " + session.expiresAt());
        }
        long liveVersion = policyStore.current().version();
        if (policyStore.current().revokes(session.deviceId())) {
            throw GatewayException.unauthorized("SESSION_REVOKED",
                    "device revoked at policy v" + liveVersion
                            + "; previously issued session is invalid immediately");
        }
        return session;
    }
}
