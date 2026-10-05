package com.github.lechandonga.zerotrustdevicegatewayjava.tests.support;

import org.junit.jupiter.api.Tag;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注测试类所覆盖的业务域名称。 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Tag("business")
public @interface BusinessDomain {
    String value();
}
