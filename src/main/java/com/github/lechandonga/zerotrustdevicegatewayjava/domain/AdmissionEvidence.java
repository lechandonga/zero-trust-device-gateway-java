package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import java.util.List;

/**
 * 一条准入结论的完整证据：
 * 用哪份挑战、按哪版规则（挑战钉住版本 + 判定实时版本）、
 * 哪把密钥（含角色）、什么度量值、逐环节结论。
 */
public record AdmissionEvidence(String challengeId,
                                long challengePolicyVersion,
                                long decisionPolicyVersion,
                                String deviceId,
                                String keyId,
                                String keyRole,
                                String measurement,
                                boolean baselineMatched,
                                boolean deviceRevokedAtDecision,
                                List<DecisionStep> steps) {
}
