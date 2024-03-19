package com.freelano.apigateway.filter;

import com.freelano.apigateway.Util.JwtUtil;
import com.freelano.apigateway.Util.RouteValidator;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;


@Component
@Slf4j
public class ApiAuthFilter extends AbstractGatewayFilterFactory<ApiAuthFilter.Config> {


    private final RouteValidator routeValidator;
    private final JwtUtil jwtUtil;

    @Autowired
    public ApiAuthFilter(RouteValidator routeValidator, JwtUtil jwtUtil) {
        super(Config.class);
        this.routeValidator = routeValidator;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            log.info("Intercepted By Auth Filter");
            ServerHttpRequest request = exchange.getRequest();
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    log.warn("No 'AUTHORIZATION' header present in request header");
                    return handleUnauthorizedResponse(exchange, "No Authorization header present");
                }
                String token;
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (Objects.nonNull(authHeader) && authHeader.startsWith("Bearer ")) {
                    token = authHeader.substring(7);
                    log.info("validation token .... ");
                    try {
                        jwtUtil.validateToken(token);
                        request = exchange
                                .getRequest()
                                .mutate()
                                .header("token", token)
                                .header("username", jwtUtil.getUsernameFromToken(token))
                                .build();
                    } catch (ExpiredJwtException e) {
                        log.error("Expired jwt");
                        return handleUnauthorizedResponse(exchange, "Expired JWT token");
                    } catch (SignatureException e) {
                        log.error("Tampered Jwt token");
                        return handleUnauthorizedResponse(exchange, "Tampered JWT token");
                    } catch (Exception e) {
                        log.error("Something went wrong while parsing the token {}", e.getMessage());
                        return handleUnauthorizedResponse(exchange, "Error parsing JWT token");
                    }
                }
            }
            return chain.filter(exchange.mutate().request(request).build());
        });
    }

    private Mono<Void> handleUnauthorizedResponse(ServerWebExchange exchange, String errorMessage) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(("{\"error\":\"" + errorMessage + "\"}").getBytes());
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Service
    public static class Config {
    }
}