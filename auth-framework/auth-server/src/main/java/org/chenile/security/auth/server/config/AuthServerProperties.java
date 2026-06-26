package org.chenile.security.auth.server.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "chenile.security.auth-server")
public class AuthServerProperties {

    private final Token token = new Token();
    private final Demo demo = new Demo();

    public Token getToken() {
        return token;
    }

    public Demo getDemo() {
        return demo;
    }

    public static class Token {
        private Map<String, String> audiences = new LinkedHashMap<>(Map.of("gateway.access", "gateway"));

        public Map<String, String> getAudiences() {
            return audiences;
        }

        public void setAudiences(Map<String, String> audiences) {
            this.audiences = audiences == null ? new LinkedHashMap<>() : audiences;
        }
    }

    public static class Demo {
        private List<Map<String, String>> credentials = new ArrayList<>();
        private List<ServiceDefinition> services = new ArrayList<>();
        private List<Scenario> scenarios = new ArrayList<>();

        public List<Map<String, String>> getCredentials() {
            return credentials;
        }

        public void setCredentials(List<Map<String, String>> credentials) {
            this.credentials = credentials == null ? new ArrayList<>() : credentials;
        }

        public List<ServiceDefinition> getServices() {
            return services;
        }

        public void setServices(List<ServiceDefinition> services) {
            this.services = services == null ? new ArrayList<>() : services;
        }

        public List<Scenario> getScenarios() {
            return scenarios;
        }

        public void setScenarios(List<Scenario> scenarios) {
            this.scenarios = scenarios == null ? new ArrayList<>() : scenarios;
        }
    }

    public static class ServiceDefinition {
        private String service;
        private String scope;
        private String audience;

        public String getService() {
            return service;
        }

        public void setService(String service) {
            this.service = service;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }
    }

    public static class Scenario {
        private String key;
        private String label;
        private String email;
        private String clientId;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }
    }
}
