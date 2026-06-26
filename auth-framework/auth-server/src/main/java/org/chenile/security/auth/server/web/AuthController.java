package org.chenile.security.auth.server.web;

import org.chenile.security.auth.server.service.TokenService;
import org.chenile.security.auth.framework.contract.TenantRegistry;
import org.chenile.security.auth.framework.contract.TenantRegistry.ClientDefinition;
import org.chenile.security.auth.framework.contract.TenantRegistry.UserDefinition;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class AuthController {

    private final TenantRegistry tenantRegistry;
    private final TokenService tokenService;

    public AuthController(TenantRegistry tenantRegistry, TokenService tokenService) {
        this.tenantRegistry = tenantRegistry;
        this.tokenService = tokenService;
    }

    @GetMapping("/realms/{tenant}/.well-known/openid-configuration")
    Map<String, Object> openIdConfiguration(@PathVariable String tenant) {
        ensureRealmExists(tenant);
        String issuer = tokenService.issuer(tenant);
        return Map.of(
                "issuer", issuer,
                "jwks_uri", issuer + "/protocol/openid-connect/certs",
                "token_endpoint", issuer + "/protocol/openid-connect/token",
                "grant_types_supported", List.of("client_credentials", "password"));
    }

    @GetMapping("/realms/{tenant}/protocol/openid-connect/certs")
    Map<String, Object> certs(@PathVariable String tenant) {
        ensureRealmExists(tenant);
        return tokenService.jwks();
    }

    @PostMapping(
            value = "/realms/{tenant}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Map<String, Object> token(
            @PathVariable String tenant,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam MultiValueMap<String, String> params) {
        ensureRealmExists(tenant);
        String grantType = required(params, "grant_type");
        String clientId = clientId(authorization, params);
        ClientDefinition client = tenantRegistry.client(tenant, clientId);
        validateClientSecret(client, authorization, params);

        List<String> scopes = requestedScopes(params);
        List<String> allowedScopes = tenantRegistry.allowedScopes(tenant, clientId, scopes);

        String accessToken = switch (grantType) {
            case "client_credentials" -> {
                if (!client.clientCredentialsEnabled()) {
                    throw unauthorized("Client credentials grant is disabled");
                }
                yield tokenService.issueClientToken(tenant, clientId, allowedScopes);
            }
            case "password" -> {
                if (!client.passwordGrantEnabled()) {
                    throw unauthorized("Password grant is disabled");
                }
                UserDefinition user = tenantRegistry.user(tenant, required(params, "username"));
                if (!tenantRegistry.matchesUserPassword(user, required(params, "password"))) {
                    throw unauthorized("Invalid user credentials");
                }
                yield tokenService.issueUserToken(tenant, clientId, user.username(), allowedScopes, user.acls());
            }
            default -> throw unauthorized("Unsupported grant type " + grantType);
        };

        return Map.of(
                "access_token", accessToken,
                "expires_in", 600,
                "scope", String.join(" ", allowedScopes),
                "token_type", "Bearer");
    }

    @PostMapping("/admin/realms")
    ResponseEntity<Map<String, Object>> createRealm(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> request) {
        requireAdmin(authorization);
        Object rawTenant = request.get("realm");
        String tenant = rawTenant == null ? null : String.valueOf(rawTenant);
        if (tenant == null || tenant.isBlank() || "null".equalsIgnoreCase(tenant)) {
            throw badRequest("realm is required");
        }
        boolean created = tenantRegistry.createRealm(tenant);
        HttpStatus status = created ? HttpStatus.CREATED : HttpStatus.CONFLICT;
        return ResponseEntity.status(status).body(tenantRegistry.createRealmPayload(tenant));
    }

    @PostMapping("/admin/realms/{tenant}/clients")
    ResponseEntity<Map<String, Object>> createClient(
            @PathVariable String tenant,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody Map<String, Object> request) {
        requireAdmin(authorization);
        ensureRealmExists(tenant);
        Object rawClientId = request.get("clientId");
        String clientId = rawClientId == null ? null : String.valueOf(rawClientId);
        if (clientId == null || clientId.isBlank() || "null".equalsIgnoreCase(clientId)) {
            throw badRequest("clientId is required");
        }
        Object rawSecret = request.get("secret");
        String secret = rawSecret == null ? null : String.valueOf(rawSecret);
        Object rawScopes = request.get("optionalClientScopes");
        List<String> scopes = rawScopes instanceof List<?> values
                ? values.stream().map(String::valueOf).toList()
                : List.of();
        tenantRegistry.registerClient(tenant, new ClientDefinition(clientId, secret, true, false, scopes));
        return ResponseEntity.created(URI.create("/admin/realms/" + tenant + "/clients/" + clientId))
                .body(new LinkedHashMap<>(Map.of("clientId", clientId, "realm", tenant)));
    }

    private void ensureRealmExists(String tenant) {
        if (!tenantRegistry.realmExists(tenant)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown realm " + tenant);
        }
    }

    private void requireAdmin(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw unauthorized("Admin bearer token is required");
        }
        if (!tokenService.isAdminToken(authorization.substring("Bearer ".length()))) {
            throw unauthorized("Invalid admin token");
        }
    }

    private void validateClientSecret(
            ClientDefinition client,
            String authorization,
            MultiValueMap<String, String> params) {
        if (client.secret() == null) {
            return;
        }
        String suppliedSecret = clientSecret(authorization, params);
        if (!tenantRegistry.matchesClientSecret(client, suppliedSecret)) {
            throw unauthorized("Invalid client credentials");
        }
    }

    private String clientId(String authorization, MultiValueMap<String, String> params) {
        if (authorization != null && authorization.startsWith("Basic ")) {
            return decodeBasic(authorization)[0];
        }
        return required(params, "client_id");
    }

    private String clientSecret(String authorization, MultiValueMap<String, String> params) {
        if (authorization != null && authorization.startsWith("Basic ")) {
            return decodeBasic(authorization)[1];
        }
        return params.getFirst("client_secret");
    }

    private String[] decodeBasic(String authorization) {
        String encoded = authorization.substring("Basic ".length());
        String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        return decoded.split(":", 2);
    }

    private List<String> requestedScopes(MultiValueMap<String, String> params) {
        String value = params.getFirst("scope");
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.of(value.trim().split("\\s+"));
    }

    private String required(MultiValueMap<String, String> params, String key) {
        String value = params.getFirst(key);
        if (value == null || value.isBlank()) {
            throw unauthorized("Missing " + key);
        }
        return value;
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private ResponseStatusException unauthorized(String message) {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, message);
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, Object>> handle(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode()).body(Map.of("error", ex.getReason()));
    }
}
