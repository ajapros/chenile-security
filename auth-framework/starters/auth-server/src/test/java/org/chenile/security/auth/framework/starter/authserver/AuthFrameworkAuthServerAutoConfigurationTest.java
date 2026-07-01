package org.chenile.security.auth.framework.starter.authserver;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class AuthFrameworkAuthServerAutoConfigurationTest {

    @Test
    void autoConfigurationLoads() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(AuthFrameworkAuthServerAutoConfiguration.class))
                .run(context -> assertThat(context).hasNotFailed());
    }
}
