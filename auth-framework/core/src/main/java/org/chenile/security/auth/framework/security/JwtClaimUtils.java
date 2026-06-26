package org.chenile.security.auth.framework.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public final class JwtClaimUtils {

    private JwtClaimUtils() {
    }

    public static String claimOrDefault(
            JwtAuthenticationToken authentication,
            String primaryClaim,
            String... fallbacks) {
        String primary = authentication.getToken().getClaimAsString(primaryClaim);
        return firstNonBlank(Stream.concat(Stream.of(primary), Arrays.stream(fallbacks)).toArray(String[]::new));
    }

    public static String firstNonBlank(String... values) {
        return Stream.of(values)
                .filter(v -> v != null && !v.isBlank())
                .findFirst()
                .orElse("unknown");
    }

    public static List<String> splitHeaderValues(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return List.of();
        }
        return Arrays.stream(headerValue.split(","))
                .map(String::trim)
                .filter(v -> !v.isBlank())
                .sorted()
                .toList();
    }

    public static List<String> extractAcls(JwtAuthenticationToken authentication) {
        List<String> roleAcls = extractClaimValues(authentication, "roles").stream()
                .filter(v -> v.contains(":"))
                .distinct()
                .sorted()
                .toList();
        if (!roleAcls.isEmpty()) {
            return roleAcls;
        }
        List<String> legacyAcls = extractClaimValues(authentication, "acls").stream()
                .filter(v -> v.contains(":"))
                .distinct()
                .sorted()
                .toList();
        if (!legacyAcls.isEmpty()) {
            return legacyAcls;
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();
    }

    private static List<String> extractClaimValues(JwtAuthenticationToken authentication, String claimName) {
        Object claim = authentication.getToken().getClaims().get(claimName);
        if (claim instanceof Collection<?> values) {
            return values.stream()
                    .map(String::valueOf)
                    .filter(v -> !v.isBlank())
                    .toList();
        }
        String singleValue = authentication.getToken().getClaimAsString(claimName);
        if (singleValue != null && !singleValue.isBlank()) {
            return List.of(singleValue);
        }
        return List.of();
    }
}
