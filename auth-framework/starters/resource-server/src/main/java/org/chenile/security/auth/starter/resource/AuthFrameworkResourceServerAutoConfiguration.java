package org.chenile.security.auth.framework.starter.resource;

import org.chenile.security.auth.framework.security.RequestSecurityContextHolder;
import org.chenile.security.auth.framework.security.ResourceServerAuthenticationManagerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class AuthFrameworkResourceServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    RequestSecurityContextHolder requestSecurityContextHolder() {
        return new RequestSecurityContextHolder();
    }

    @Bean
    @ConditionalOnMissingBean
    ResourceServerAuthenticationManagerFactory resourceServerAuthenticationManagerFactory() {
        return new ResourceServerAuthenticationManagerFactory();
    }
}
