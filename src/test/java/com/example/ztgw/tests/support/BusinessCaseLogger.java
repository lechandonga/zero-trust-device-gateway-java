package com.example.ztgw.tests.support;

import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

/**
 * Prints one business-oriented line before and after every case, so unit-test
 * logs show which business flows and edge cases were exercised and their
 * outcomes.
 */
public class BusinessCaseLogger implements BeforeEachCallback, AfterTestExecutionCallback {

    private static final Logger log = LoggerFactory.getLogger("BUSINESS-CASE");

    @Override
    public void beforeEach(ExtensionContext context) {
        log.info(">>> [{}] START case: {}", business(context), caseName(context));
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        boolean failed = context.getExecutionException().isPresent();
        log.info("<<< [{}] {} case: {}", business(context), failed ? "FAIL" : "PASS", caseName(context));
    }

    private String business(ExtensionContext context) {
        return context.getTestClass().map(Class::getSimpleName).orElse("unknown");
    }

    private String caseName(ExtensionContext context) {
        return context.getTestMethod().map(Method::getName).orElse("unknown");
    }
}
