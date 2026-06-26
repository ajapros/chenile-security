package org.chenile.security.auth.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebCorsConfig implements WebMvcConfigurer {

    private final String[] allowedOriginPatterns;

    public WebCorsConfig(@Value("${chenile.security.demo-ui.allowed-origins:http://localhost:5173,http://127.0.0.1:5173}") String allowedOrigins) {
        this.allowedOriginPatterns = allowedOrigins.split(",");
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOriginPatterns(trimmedOriginPatterns())
                .allowedMethods("GET", "POST", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }

    private String[] trimmedOriginPatterns() {
        return java.util.Arrays.stream(allowedOriginPatterns)
                .map(String::trim)
                .filter(v -> !v.isBlank())
                .toArray(String[]::new);
    }
}
