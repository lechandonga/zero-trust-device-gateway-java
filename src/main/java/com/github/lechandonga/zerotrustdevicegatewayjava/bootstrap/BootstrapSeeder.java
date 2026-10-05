package com.github.lechandonga.zerotrustdevicegatewayjava.bootstrap;

import com.github.lechandonga.zerotrustdevicegatewayjava.config.GatewayProperties;
import com.github.lechandonga.zerotrustdevicegatewayjava.service.EnrollmentService;
import com.github.lechandonga.zerotrustdevicegatewayjava.service.PolicyService;
import com.github.lechandonga.zerotrustdevicegatewayjava.store.TokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * 本地演示播种：启动后创建一个一次性入网令牌并发布受信基线策略，
 * 使“首次入网 → 证明 → 轮换”链路无需任何外部准备即可验证。
 */
@Component
public class BootstrapSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapSeeder.class);

    private final GatewayProperties properties;
    private final EnrollmentService enrollmentService;
    private final PolicyService policyService;
    private final TokenStore tokenStore;

    public BootstrapSeeder(GatewayProperties properties,
                           EnrollmentService enrollmentService,
                           PolicyService policyService,
                           TokenStore tokenStore) {
        this.properties = properties;
        this.enrollmentService = enrollmentService;
        this.policyService = policyService;
        this.tokenStore = tokenStore;
    }

    @Override
    public void run(ApplicationArguments args) {
        String token = properties.getBootstrapToken();
        if (token != null && !token.isBlank() && tokenStore.find(token).isEmpty()) {
            enrollmentService.issueToken(token, properties.getBootstrapDevice());
            log.info("[bootstrap] one-time enrollment token seeded: value={}, boundDevice={}, ttl={}",
                    token, properties.getBootstrapDevice(), properties.getEnrollmentTtl());
        }
        if (!policyService.current().trustsMeasurement(properties.getBootstrapMeasurement())) {
            var published = policyService.publish(
                    Set.of(properties.getBootstrapMeasurement()),
                    policyService.current().revokedDevices(),
                    "bootstrap trusted firmware baseline");
            log.info("[bootstrap] trusted baseline published as policy v{}: {}",
                    published.version(), properties.getBootstrapMeasurement());
        }
    }
}
