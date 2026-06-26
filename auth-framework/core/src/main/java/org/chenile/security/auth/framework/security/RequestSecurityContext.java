package org.chenile.security.auth.framework.security;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

public record RequestSecurityContext(
        String userId,
        String tenantId,
        List<String> acls,
        String bearerToken,
        String headerUserId,
        String headerTenantId,
        List<String> headerAcls) {

    public Map<String, Object> asMap() {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("userId", userId);
        values.put("tenantId", tenantId);
        values.put("acls", acls);
        values.put("headerUserId", headerUserId);
        values.put("headerTenantId", headerTenantId);
        values.put("headerAcls", headerAcls);
        return values;
    }
}
