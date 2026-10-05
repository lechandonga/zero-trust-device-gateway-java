package com.github.lechandonga.zerotrustdevicegatewayjava.tests.support;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 让单测日志清晰体现“覆盖了哪些业务、每个业务下有哪些用例、结果如何”：
 * 类级（=一个业务域）开始时打印业务横幅，每个用例打印 ✔/✘ 结果，
 * 业务域结束时打印通过/失败汇总。
 */
public class BusinessLoggingExtension implements BeforeAllCallback, AfterEachCallback,
        AfterAllCallback, TestWatcher {

    private static final Logger log = LoggerFactory.getLogger("BUSINESS-TESTS");

    private static final Map<Class<?>, List<String>> PASSED = new ConcurrentHashMap<>();
    private static final Map<Class<?>, List<String>> FAILED = new ConcurrentHashMap<>();

    @Override
    public void beforeAll(ExtensionContext context) {
        String business = businessName(context);
        log.info("");
        log.info("==================== 业务域: {} ====================", business);
        log.info("开始执行业务用例集合: {}", business);
    }

    @Override
    public void afterEach(ExtensionContext context) {
        // 结果由 testSuccessful / testFailed 打印，这里无需处理。
    }

    @Override
    public void testSuccessful(ExtensionContext context) {
        counters(PASSED, context.getRequiredTestClass()).add(context.getDisplayName());
        log.info("  [✔ 通过] 用例: {}", context.getDisplayName());
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        String failure = context.getDisplayName() + " -> "
                + cause.getClass().getSimpleName() + ": " + cause.getMessage();
        counters(FAILED, context.getRequiredTestClass()).add(failure);
        log.info("  [✘ 失败] 用例: {}，原因: {}", context.getDisplayName(), cause.getMessage());
    }

    @Override
    public void testAborted(ExtensionContext context, Throwable cause) {
        log.info("  [○ 中止] 用例: {}", context.getDisplayName());
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        log.info("  [－ 跳过] 用例: {}，原因: {}", context.getDisplayName(), reason.orElse(""));
    }

    @Override
    public void afterAll(ExtensionContext context) {
        Class<?> testClass = context.getRequiredTestClass();
        List<String> passed = PASSED.getOrDefault(testClass, List.of());
        List<String> failed = FAILED.getOrDefault(testClass, List.of());
        log.info("业务域 [{}] 执行完毕: 共 {} 个用例，通过 {}，失败 {}",
                businessName(context), passed.size() + failed.size(), passed.size(), failed.size());
        if (!failed.isEmpty()) {
            failed.forEach(item -> log.info("    失败明细: {}", item));
        }
        log.info("====================================================");
        log.info("");
        PASSED.remove(testClass);
        FAILED.remove(testClass);
    }

    private String businessName(ExtensionContext context) {
        Class<?> testClass = context.getRequiredTestClass();
        BusinessDomain annotation = testClass.getAnnotation(BusinessDomain.class);
        return annotation != null ? annotation.value() : testClass.getSimpleName();
    }

    private List<String> counters(Map<Class<?>, List<String>> counters, Class<?> testClass) {
        return counters.computeIfAbsent(testClass, key -> java.util.Collections.synchronizedList(new ArrayList<>()));
    }
}
