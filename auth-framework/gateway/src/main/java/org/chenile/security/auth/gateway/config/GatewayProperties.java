package org.chenile.security.auth.gateway.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "chenile.security.gateway")
public class GatewayProperties {

    private final AuthServer authServer = new AuthServer();
    private final Security security = new Security();
    private final Relay relay = new Relay();
    private List<Route> routes = new ArrayList<>();

    public AuthServer getAuthServer() {
        return authServer;
    }

    public Security getSecurity() {
        return security;
    }

    public Relay getRelay() {
        return relay;
    }

    public List<Route> getRoutes() {
        return routes;
    }

    public static class Relay {
        private boolean forwardAuthorization = true;
        private List<Header> headers = new ArrayList<>(List.of(
                header("x-tenant-id", "tenant"),
                header("x-user-id", "user_id"),
                header("x-acls", "acls")));

        public boolean isForwardAuthorization() {
            return forwardAuthorization;
        }

        public void setForwardAuthorization(boolean forwardAuthorization) {
            this.forwardAuthorization = forwardAuthorization;
        }

        public List<Header> getHeaders() {
            return headers;
        }

        public void setHeaders(List<Header> headers) {
            this.headers = headers == null ? new ArrayList<>() : headers;
        }

        private static Header header(String name, String claim) {
            Header header = new Header();
            header.setName(name);
            header.setClaim(claim);
            return header;
        }
    }

    public static class Header {
        private String name;
        private String claim;
        private String format = "string";

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getClaim() {
            return claim;
        }

        public void setClaim(String claim) {
            this.claim = claim;
        }

        public String getFormat() {
            return format;
        }

        public void setFormat(String format) {
            this.format = format;
        }
    }

    public void setRoutes(List<Route> routes) {
        this.routes = routes == null ? new ArrayList<>() : routes;
    }

    public static class AuthServer {
        private String uri = "http://localhost:9000";
        private List<String> paths = new ArrayList<>(List.of("/realms/**", "/resources/**"));

        public String getUri() {
            return uri;
        }

        public void setUri(String uri) {
            this.uri = uri;
        }

        public List<String> getPaths() {
            return paths;
        }

        public void setPaths(List<String> paths) {
            this.paths = paths == null ? new ArrayList<>() : paths;
        }
    }

    public static class Security {
        private String requiredScope = "gateway.access";
        private String audience = "gateway";
        private String issuerBase = "http://localhost:9000";
        private String jwkBaseUri = "http://localhost:9000";
        private List<String> publicPaths = new ArrayList<>(
                List.of("/actuator/health", "/actuator/info", "/realms/**", "/resources/**", "/public/**"));

        public String getRequiredScope() {
            return requiredScope;
        }

        public void setRequiredScope(String requiredScope) {
            this.requiredScope = requiredScope;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getIssuerBase() {
            return issuerBase;
        }

        public void setIssuerBase(String issuerBase) {
            this.issuerBase = issuerBase;
        }

        public String getJwkBaseUri() {
            return jwkBaseUri;
        }

        public void setJwkBaseUri(String jwkBaseUri) {
            this.jwkBaseUri = jwkBaseUri;
        }

        public List<String> getPublicPaths() {
            return publicPaths;
        }

        public void setPublicPaths(List<String> publicPaths) {
            this.publicPaths = publicPaths == null ? new ArrayList<>() : publicPaths;
        }
    }

    public static class Route {
        private String id;
        private List<String> paths = new ArrayList<>();
        private String uri;
        private String rewriteRegex;
        private String rewriteReplacement;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public List<String> getPaths() {
            return paths;
        }

        public void setPaths(List<String> paths) {
            this.paths = paths == null ? new ArrayList<>() : paths;
        }

        public String getUri() {
            return uri;
        }

        public void setUri(String uri) {
            this.uri = uri;
        }

        public String getRewriteRegex() {
            return rewriteRegex;
        }

        public void setRewriteRegex(String rewriteRegex) {
            this.rewriteRegex = rewriteRegex;
        }

        public String getRewriteReplacement() {
            return rewriteReplacement;
        }

        public void setRewriteReplacement(String rewriteReplacement) {
            this.rewriteReplacement = rewriteReplacement;
        }
    }
}
