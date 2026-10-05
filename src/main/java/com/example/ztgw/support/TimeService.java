package com.example.ztgw.support;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Single clock used by every service so that TTL checks are testable without
 * real waiting. Production code sees the system clock; tests may advance it.
 */
@Component
public class TimeService {

    private final Instant bootBase = Instant.now();
    private volatile Duration offset = Duration.ZERO;

    public Instant now() {
        return Instant.now().plus(offset);
    }

    /** Test-only: move every TTL/expiry clock forward by the given duration. */
    public void advance(Duration duration) {
        this.offset = offset.plus(duration);
    }

    public Duration uptime() {
        return Duration.between(bootBase, now());
    }
}
