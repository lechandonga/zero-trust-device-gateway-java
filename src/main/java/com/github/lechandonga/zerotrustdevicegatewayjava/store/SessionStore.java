package com.github.lechandonga.zerotrustdevicegatewayjava.store;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionSession;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 准入会话存储。会话是否有效由服务层结合实时策略判定，
 * 因此吊销设备无需遍历或改写会话即可立即生效。
 */
@Component
public class SessionStore {

    private final ConcurrentMap<String, AdmissionSession> sessions = new ConcurrentHashMap<>();

    public AdmissionSession put(AdmissionSession session) {
        sessions.put(session.sessionId(), session);
        return session;
    }

    public Optional<AdmissionSession> find(String sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }
}
