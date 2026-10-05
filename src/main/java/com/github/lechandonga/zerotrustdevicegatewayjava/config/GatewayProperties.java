package com.github.lechandonga.zerotrustdevicegatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 网关本地可调参数。所有参数均有默认值，开箱即可本地完整跑通。
 */
@ConfigurationProperties(prefix = "ztgw")
public class GatewayProperties {

    /** 一次性入网令牌有效期。 */
    private Duration enrollmentTtl = Duration.ofMinutes(10);

    /** 证明挑战有效期。 */
    private Duration challengeTtl = Duration.ofMinutes(2);

    /** 准入会话有效期。 */
    private Duration sessionTtl = Duration.ofMinutes(5);

    /** 首次启动时自动播种的演示令牌（为空则不播种）。 */
    private String bootstrapToken = "BOOTSTRAP-TOKEN-2026";

    /** 演示令牌绑定的设备标识（为空表示不绑定设备）。 */
    private String bootstrapDevice = "demo-device-001";

    /** 演示环境的受信固件度量值（SHA-256 十六进制）。 */
    private String bootstrapMeasurement =
            "a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff00";

    /** 密钥轮换默认宽限期（请求中未显式指定时使用）。 */
    private Duration defaultRotationGrace = Duration.ofMinutes(2);

    public Duration getEnrollmentTtl() { return enrollmentTtl; }
    public void setEnrollmentTtl(Duration enrollmentTtl) { this.enrollmentTtl = enrollmentTtl; }
    public Duration getChallengeTtl() { return challengeTtl; }
    public void setChallengeTtl(Duration challengeTtl) { this.challengeTtl = challengeTtl; }
    public Duration getSessionTtl() { return sessionTtl; }
    public void setSessionTtl(Duration sessionTtl) { this.sessionTtl = sessionTtl; }
    public String getBootstrapToken() { return bootstrapToken; }
    public void setBootstrapToken(String bootstrapToken) { this.bootstrapToken = bootstrapToken; }
    public String getBootstrapDevice() { return bootstrapDevice; }
    public void setBootstrapDevice(String bootstrapDevice) { this.bootstrapDevice = bootstrapDevice; }
    public String getBootstrapMeasurement() { return bootstrapMeasurement; }
    public void setBootstrapMeasurement(String bootstrapMeasurement) { this.bootstrapMeasurement = bootstrapMeasurement; }
    public Duration getDefaultRotationGrace() { return defaultRotationGrace; }
    public void setDefaultRotationGrace(Duration defaultRotationGrace) { this.defaultRotationGrace = defaultRotationGrace; }
}
