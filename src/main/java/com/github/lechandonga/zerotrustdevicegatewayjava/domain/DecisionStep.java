package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

/**
 * 准入判定过程中的一个检查环节，构成可解释的证据链。
 */
public record DecisionStep(String check, boolean passed, String detail) {

    public static DecisionStep of(String check, boolean passed, String detail) {
        return new DecisionStep(check, passed, detail);
    }
}
