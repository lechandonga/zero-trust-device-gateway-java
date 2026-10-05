package com.example.ztgw.error;

import java.time.Instant;
import java.util.Map;

public record ApiError(String code, String message, Instant at, Map<String, Object> details) {
}
