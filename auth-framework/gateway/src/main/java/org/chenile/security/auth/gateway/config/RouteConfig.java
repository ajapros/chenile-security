package org.chenile.security.auth.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
public class RouteConfig {

    @Bean
    RouteLocator routeLocator(RouteLocatorBuilder builder, GatewayProperties properties) {
        RouteLocatorBuilder.Builder routes = builder.routes()
                .route("identity-provider", route -> route
                        .path(properties.getAuthServer().getPaths().toArray(String[]::new))
                        .uri(properties.getAuthServer().getUri()));

        for (GatewayProperties.Route configuredRoute : properties.getRoutes()) {
            routes.route(configuredRoute.getId(), route -> {
                var predicate = route.path(configuredRoute.getPaths().toArray(String[]::new));
                if (StringUtils.hasText(configuredRoute.getRewriteRegex())
                        && StringUtils.hasText(configuredRoute.getRewriteReplacement())) {
                    return predicate
                            .filters(filters -> filters.rewritePath(
                                    configuredRoute.getRewriteRegex(),
                                    configuredRoute.getRewriteReplacement()))
                            .uri(configuredRoute.getUri());
                }
                return predicate.uri(configuredRoute.getUri());
            });
        }
        return routes.build();
    }
}
