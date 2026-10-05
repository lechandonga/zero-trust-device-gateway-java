package com.github.lechandonga.zerotrustdevicegatewayjava.service;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.AdmissionEvidence;
import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import org.springframework.http.HttpStatus;

/**
 * 证明被拒：除错误码外携带已经收集到的证据链，便于调用方解释拒绝原因。
 */
public class AttestationDeniedException extends GatewayException {

    private final transient AdmissionEvidence evidence;

    public AttestationDeniedException(String code, String message, HttpStatus status,
                                      AdmissionEvidence evidence) {
        super(code, message, status);
        this.evidence = evidence;
    }

    public AdmissionEvidence evidence() {
        return evidence;
    }
}
