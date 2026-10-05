package com.github.lechandonga.zerotrustdevicegatewayjava.domain;

import org.springframework.http.HttpStatus;

/**
 * 业务异常：携带可区分的机器可读错误码与 HTTP 状态，
 * 失败原因必须对调用方可区分、可解释。
 */
public class GatewayException extends RuntimeException {

    private final String code;
    private final HttpStatus status;

    public GatewayException(String code, String message, HttpStatus status) {
        super(message);
        this.code = code;
        this.status = status;
    }

    public String code() {
        return code;
    }

    public HttpStatus status() {
        return status;
    }

    public static GatewayException badRequest(String code, String message) {
        return new GatewayException(code, message, HttpStatus.BAD_REQUEST);
    }

    public static GatewayException unauthorized(String code, String message) {
        return new GatewayException(code, message, HttpStatus.UNAUTHORIZED);
    }

    public static GatewayException notFound(String code, String message) {
        return new GatewayException(code, message, HttpStatus.NOT_FOUND);
    }

    public static GatewayException conflict(String code, String message) {
        return new GatewayException(code, message, HttpStatus.CONFLICT);
    }
}
