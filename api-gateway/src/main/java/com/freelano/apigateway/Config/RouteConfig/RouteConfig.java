package com.freelano.apigateway.Config.RouteConfig;

import com.freelano.apigateway.filter.ApiAuthFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class RouteConfig {

    private final ApiAuthFilter authorizationFilter;

    @Autowired
    public RouteConfig(ApiAuthFilter authorizationFilter) {
        this.authorizationFilter = authorizationFilter;
    }

    @Bean
    public RouteLocator gatewayRouter(RouteLocatorBuilder builder) {

        return builder.routes()
                .route(path ->
                        path.path("/api/v1/auth/**")
                                .filters(f -> f.filter(authorizationFilter.apply(new ApiAuthFilter.Config())))
                                .uri("lb://auth-service"))
                .build();
    }

}