package com.example.ztgw.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ztg")
public class ZtgProperties {

    private long tokenTtlSeconds = 300;
    private long challengeTtlSeconds = 60;
    private long sessionTtlSeconds = 120;
    private long rotationGraceSeconds = 300;

    public long getTokenTtlSeconds() {
        return tokenTtlSeconds;
    }

    public void setTokenTtlSeconds(long tokenTtlSeconds) {
        this.tokenTtlSeconds = tokenTtlSeconds;
    }

    public long getChallengeTtlSeconds() {
        return challengeTtlSeconds;
    }

    public void setChallengeTtlSeconds(long challengeTtlSeconds) {
        this.challengeTtlSeconds = challengeTtlSeconds;
    }

    public long getSessionTtlSeconds() {
        return sessionTtlSeconds;
    }

    public void setSessionTtlSeconds(long sessionTtlSeconds) {
        this.sessionTtlSeconds = sessionTtlSeconds;
    }

    public long getRotationGraceSeconds() {
        return rotationGraceSeconds;
    }

    public void setRotationGraceSeconds(long rotationGraceSeconds) {
        this.rotationGraceSeconds = rotationGraceSeconds;
    }
}
