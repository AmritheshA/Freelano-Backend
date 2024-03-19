package com.freelano.apigateway.Util;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {
    public static final List<String> allowedEndPoints = List.of(
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/google/oauth/login",
            "/eureka"
    );
    public Predicate<ServerHttpRequest> isSecured =
            serverHttpRequest -> allowedEndPoints.stream().noneMatch(url ->
                    serverHttpRequest.getURI().getPath().contains(url));
}