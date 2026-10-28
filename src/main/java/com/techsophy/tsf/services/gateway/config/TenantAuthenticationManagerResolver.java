package com.techsophy.tsf.services.gateway.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.*;

@Component
@Slf4j
public class TenantAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {
    private final Map<String, ReactiveAuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();

    @Value("${keycloak.issuer-uri}")
    private String keycloakIssuerUri;

    @Autowired
    private TenantRegistration tenants;

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange request) {
        String tenant;
        try {
            tenant = getIssuerFromToken(request.getRequest().getHeaders().getFirst("Authorization"));
        } catch (ParseException e) {
            return Mono.error(bearerTokenException(HttpStatus.FORBIDDEN, MALFORMED_TOKEN));
        }
        // same parsing as KeycloakRealmRepository: a single comma separated entry
        if (!Arrays.asList(tenants.getRegistrations().get(0).split(",")).contains(tenant)) {
            return Mono.error(bearerTokenException(HttpStatus.UNAUTHORIZED, INVALID_TENANT));
        }
        // the realm's OpenID configuration could not be loaded; nothing is cached, so the next request retries
        return Mono.fromCallable(() -> this.authenticationManagers.computeIfAbsent(tenant, this::fromTenant))
                .onErrorMap(TenantAuthenticationManagerResolver::keycloakUnavailable);
    }

    public static String toTenant(ServerWebExchange request) {
        String stoken = request.getRequest().getHeaders().getFirst("Authorization");
        if (stoken == null) {
            return null;
        }
        try {
            return getIssuerFromToken(stoken);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private ReactiveAuthenticationManager fromTenant(String tenant) {
        JwtReactiveAuthenticationManager authenticationManager =
                new JwtReactiveAuthenticationManager(ReactiveJwtDecoders.fromIssuerLocation(keycloakIssuerUri + tenant));
        // Spring reports every rejected token as 401; claim validation failures (expiry, issuer) stay 401,
        // structure and signature failures become 403
        return authentication -> authenticationManager.authenticate(authentication)
                .onErrorMap(e -> e instanceof InvalidBearerTokenException && !(e.getCause() instanceof JwtValidationException),
                        e -> bearerTokenException(HttpStatus.FORBIDDEN, INVALID_TOKEN))
                // the decoder reports a failed signing key (JWKS) fetch as IllegalStateException
                .onErrorMap(IllegalStateException.class, TenantAuthenticationManagerResolver::keycloakUnavailable);
    }

    private static OAuth2AuthenticationException bearerTokenException(HttpStatus status, String description) {
        return new OAuth2AuthenticationException(new BearerTokenError(BearerTokenErrorCodes.INVALID_TOKEN, status, description, null));
    }

    private static ResponseStatusException keycloakUnavailable(Throwable e) {
        log.error(KEYCLOAK_UNAVAILABLE + ": " + NestedExceptionUtils.getMostSpecificCause(e).getMessage());
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, KEYCLOAK_UNAVAILABLE, e);
    }

    public static String getIssuerFromToken(String idToken) throws ParseException {
        if (idToken.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            idToken = idToken.substring(BEARER.length());
        }
        JWTClaimsSet claims = JWTParser.parse(idToken).getJWTClaimsSet();
        if (claims == null) {
            throw new ParseException(MALFORMED_TOKEN, 0);
        }
        String issuer = claims.getIssuer();
        return issuer == null ? "" : issuer.substring(issuer.lastIndexOf('/') + 1);
    }
}
