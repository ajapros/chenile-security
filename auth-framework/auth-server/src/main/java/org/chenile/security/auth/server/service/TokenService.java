package org.chenile.security.auth.server.service;

import org.chenile.security.auth.server.config.AuthServerProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final String issuerBase;
    private final AuthServerProperties properties;
    private final RSAKey rsaKey;

    public TokenService(
            @Value("${chenile.security.issuer-base:http://localhost:9000}") String issuerBase,
            AuthServerProperties properties) {
        this.issuerBase = issuerBase;
        this.properties = properties;
        this.rsaKey = generateKey();
    }

    public String issuer(String tenant) {
        return issuerBase + "/realms/" + tenant;
    }

    public Map<String, Object> jwks() {
        return new JWKSet(rsaKey.toPublicJWK()).toJSONObject();
    }

    public String issueClientToken(String tenant, String clientId, List<String> scopes) {
        return signToken(tenant, clientId, clientId, scopes, List.of(), clientId, Map.of("tenant", tenant));
    }

    public String issueUserToken(String tenant, String clientId, String username, List<String> scopes, List<String> acls) {
        return issueUserToken(tenant, clientId, username, scopes, acls, Map.of());
    }

    public String issueUserToken(
            String tenant,
            String clientId,
            String username,
            List<String> scopes,
            List<String> acls,
            Map<String, Object> additionalClaims) {
        return issueUserToken(tenant, clientId, username, username, scopes, acls, additionalClaims);
    }

    public String issueUserToken(
            String tenant,
            String clientId,
            String username,
            String userId,
            List<String> scopes,
            List<String> acls,
            Map<String, Object> additionalClaims) {
        java.util.LinkedHashMap<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("tenant", tenant);
        claims.putAll(additionalClaims);
        return signToken(tenant, username, clientId, scopes, acls, userId, claims);
    }

    public boolean isAdminToken(String tokenValue) {
        try {
            List<String> roles = verifiedClaims(tokenValue).getStringListClaim("roles");
            return roles != null && roles.contains("iam:admin");
        } catch (Exception ex) {
            return false;
        }
    }

    public JWTClaimsSet verifiedClaims(String tokenValue) {
        try {
            SignedJWT jwt = SignedJWT.parse(tokenValue);
            if (!jwt.verify(new RSASSAVerifier(rsaKey.toRSAPublicKey()))) {
                throw new IllegalArgumentException("Token signature verification failed");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date expirationTime = claims.getExpirationTime();
            if (expirationTime != null && expirationTime.toInstant().isBefore(Instant.now())) {
                throw new IllegalArgumentException("Token expired");
            }
            return claims;
        } catch (ParseException | JOSEException ex) {
            throw new IllegalArgumentException("Invalid token", ex);
        }
    }

    private String signToken(
            String tenant,
            String subject,
            String authorizedParty,
            List<String> scopes,
            List<String> acls,
            String userId,
            Map<String, Object> additionalClaims) {
        try {
            Instant now = Instant.now();
            Set<String> audiences = new LinkedHashSet<>();
            for (String scope : scopes) {
                String audience = properties.getToken().getAudiences().get(scope);
                if (audience != null) {
                    audiences.add(audience);
                }
            }

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(issuer(tenant))
                    .subject(subject)
                    .claim("azp", authorizedParty)
                    .claim("user_id", userId)
                    .claim("preferred_username", subject)
                    .claim("scope", String.join(" ", scopes))
                    .claim("scp", scopes)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(600)))
                    .jwtID(UUID.randomUUID().toString());

            if (!audiences.isEmpty()) {
                claims.audience(List.copyOf(audiences));
            }
            if (!acls.isEmpty()) {
                claims.claim("roles", acls);
                claims.claim("acls", acls);
            }
            additionalClaims.forEach(claims::claim);

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                    claims.build());
            jwt.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Failed to sign token", ex);
        }
    }

    private RSAKey generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID("spring-auth-key")
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key", ex);
        }
    }
}
