package org.chenile.security.auth.framework.security;

import java.net.URI;
import org.springframework.security.oauth2.jwt.Jwt;

public final class IssuerTenantResolver {

    private static final String REALMS_SEGMENT = "/realms/";

    private IssuerTenantResolver() {
    }

    public static String tenantFromJwt(Jwt jwt) {
        return tenantFromIssuer(jwt.getIssuer() == null ? null : jwt.getIssuer().toString());
    }

    public static String tenantFromIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return "unknown";
        }
        String path = URI.create(issuer).getPath();
        int realmIndex = path.indexOf(REALMS_SEGMENT);
        if (realmIndex < 0) {
            return "unknown";
        }
        String realm = path.substring(realmIndex + REALMS_SEGMENT.length());
        int nextSlash = realm.indexOf('/');
        return nextSlash >= 0 ? realm.substring(0, nextSlash) : realm;
    }

}
