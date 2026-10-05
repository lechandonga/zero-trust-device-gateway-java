package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import java.time.Instant;

/**
 * 短期准入会话。发放时的证据与规则版本永久固定，不随后续策略更新而改写；
 * 是否仍有效则在每次使用时按实时吊销名单判断，实现“吊销立即生效”。
 */
public record AdmissionSession(String sessionId,
                               String deviceId,
                               Instant issuedAt,
                               Instant expiresAt,
                               AdmissionEvidence evidence) {
}
