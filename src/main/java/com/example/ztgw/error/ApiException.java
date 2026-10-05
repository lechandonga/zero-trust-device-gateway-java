package com.example.ztgw.error;

import org.springframework.http.HttpStatus;

import java.util.Map;

public class ApiException extends RuntimeException {

    private final String code;
    private final HttpStatus status;
    private final Map<String, Object> details;

    public ApiException(String code, String message, HttpStatus status) {
        this(code, message, status, Map.of());
    }

    public ApiException(String code, String message, HttpStatus status, Map<String, Object> details) {
        super(message);
        this.code = code;
        this.status = status;
        this.details = details;
    }

    public String getCode() {
        return code;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public ApiException withDetails(Map<String, Object> details) {
        return new ApiException(code, getMessage(), status, details);
    }

    public static ApiException notFound(String code, String message) {
        return new ApiException(code, message, HttpStatus.NOT_FOUND);
    }

    public static ApiException notFound(String code, String message, Map<String, Object> details) {
        return new ApiException(code, message, HttpStatus.NOT_FOUND, details);
    }

    public static ApiException conflict(String code, String message) {
        return new ApiException(code, message, HttpStatus.CONFLICT);
    }

    public static ApiException conflict(String code, String message, Map<String, Object> details) {
        return new ApiException(code, message, HttpStatus.CONFLICT, details);
    }

    public static ApiException badRequest(String code, String message) {
        return new ApiException(code, message, HttpStatus.BAD_REQUEST);
    }

    public static ApiException badRequest(String code, String message, Map<String, Object> details) {
        return new ApiException(code, message, HttpStatus.BAD_REQUEST, details);
    }

    public static ApiException forbidden(String code, String message) {
        return new ApiException(code, message, HttpStatus.FORBIDDEN);
    }

    public static ApiException forbidden(String code, String message, Map<String, Object> details) {
        return new ApiException(code, message, HttpStatus.FORBIDDEN, details);
    }

    public static ApiException preconditionFailed(String code, String message) {
        return new ApiException(code, message, HttpStatus.PRECONDITION_FAILED);
    }
}
