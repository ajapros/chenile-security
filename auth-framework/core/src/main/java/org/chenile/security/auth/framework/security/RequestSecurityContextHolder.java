package org.chenile.security.auth.framework.security;

public class RequestSecurityContextHolder {

    private static final ThreadLocal<RequestSecurityContext> CONTEXT = new ThreadLocal<>();

    public void set(RequestSecurityContext context) {
        CONTEXT.set(context);
    }

    public RequestSecurityContext getRequired() {
        RequestSecurityContext context = CONTEXT.get();
        if (context == null) {
            throw new IllegalStateException("Request security context is not available");
        }
        return context;
    }

    public void clear() {
        CONTEXT.remove();
    }
}
