package org.chenile.security.auth.framework.starter.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class AuthFrameworkGatewayAutoConfigurationTest {

    @Test
    void autoConfigurationLoads() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(AuthFrameworkGatewayAutoConfiguration.class))
                .run(context -> assertThat(context).hasNotFailed());
    }
}
