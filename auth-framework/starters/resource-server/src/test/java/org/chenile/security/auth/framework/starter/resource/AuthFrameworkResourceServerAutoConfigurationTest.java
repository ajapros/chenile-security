package org.chenile.security.auth.framework.starter.resource;

import static org.assertj.core.api.Assertions.assertThat;

import org.chenile.security.auth.framework.security.RequestSecurityContextHolder;
import org.chenile.security.auth.framework.security.ResourceServerAuthenticationManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class AuthFrameworkResourceServerAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthFrameworkResourceServerAutoConfiguration.class));

    @Test
    void createsDefaultResourceServerSupportBeans() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(RequestSecurityContextHolder.class);
            assertThat(context).hasSingleBean(ResourceServerAuthenticationManagerFactory.class);
        });
    }

    @Test
    void doesNotOverrideApplicationProvidedBeans() {
        contextRunner.withUserConfiguration(UserBeans.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(RequestSecurityContextHolder.class);
                    assertThat(context).hasSingleBean(ResourceServerAuthenticationManagerFactory.class);
                    assertThat(context.getBean(RequestSecurityContextHolder.class)).isSameAs(context.getBean("customHolder"));
                    assertThat(context.getBean(ResourceServerAuthenticationManagerFactory.class)).isSameAs(context.getBean("customFactory"));
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class UserBeans {

        @Bean
        RequestSecurityContextHolder customHolder() {
            return new RequestSecurityContextHolder();
        }

        @Bean
        ResourceServerAuthenticationManagerFactory customFactory() {
            return new ResourceServerAuthenticationManagerFactory();
        }
    }
}
