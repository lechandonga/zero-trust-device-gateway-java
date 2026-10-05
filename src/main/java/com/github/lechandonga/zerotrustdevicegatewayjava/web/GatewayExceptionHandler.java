package com.github.lechandonga.zerotrustdevicegatewayjava.web;

import com.github.lechandonga.zerotrustdevicegatewayjava.domain.GatewayException;
import com.github.lechandonga.zerotrustdevicegatewayjava.service.AttestationDeniedException;
import com.github.lechandonga.zerotrustdevicegatewayjava.web.dto.Views;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一错误响应：{ code, message, evidence }，失败原因可区分、可解释。
 */
@RestControllerAdvice
public class GatewayExceptionHandler {

    @ExceptionHandler(AttestationDeniedException.class)
    public ResponseEntity<Views.ErrorResponse> denied(AttestationDeniedException ex) {
        return ResponseEntity.status(ex.status())
                .body(new Views.ErrorResponse(ex.code(), ex.getMessage(), ex.evidence()));
    }

    @ExceptionHandler(GatewayException.class)
    public ResponseEntity<Views.ErrorResponse> gateway(GatewayException ex) {
        return ResponseEntity.status(ex.status())
                .body(new Views.ErrorResponse(ex.code(), ex.getMessage(), null));
    }
}
