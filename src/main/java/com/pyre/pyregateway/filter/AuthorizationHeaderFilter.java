package com.pyre.pyregateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.couchbase.CouchbaseProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.UUID;


@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final Key secret;
    public AuthorizationHeaderFilter(
         @Value("${jwt.secret.key}")
         String secretKey) {
        super(Config.class);
        this.secret = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange,"JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            String jwts = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            String jwt = null;
            if (StringUtils.hasText(jwts) && jwts.startsWith("Bearer ")) {
                jwt = jwts.substring(7);
            }
            if (!isJwtValid(jwt)) {
                log.info("jwt 검증 실패");
                return onError(exchange,"JWT token is not valid",HttpStatus.UNAUTHORIZED);
            }

            String id = String.valueOf(Jwts.parserBuilder().setSigningKey(secret).build()
                    .parseClaimsJws(jwt).getBody().get("id"));

            ServerHttpRequest req = exchange.getRequest().mutate().header("id", id).build();

            return chain.filter(exchange.mutate().request(req).build());
        }));
    }
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
        String subject = null;
        try {
            subject = Jwts.parser().setSigningKey(secret)
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();
        } catch (Exception ex) {
            returnValue = false;
        }

        if (subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        return returnValue;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();

    }

    public static class Config {

    }
}