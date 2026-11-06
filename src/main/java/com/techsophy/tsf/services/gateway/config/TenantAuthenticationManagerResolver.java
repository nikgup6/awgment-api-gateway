package com.techsophy.tsf.services.gateway.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.*;

@Component
@Slf4j
public class TenantAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {
    private static final Pattern AUTH_SCHEME = Pattern.compile("[A-Za-z][A-Za-z0-9-]{0,19}");
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
            return Mono.error(invalidToken(MALFORMED_TOKEN));
        }
        // only realms in tenants.registrations are trusted, even if Keycloak hosts others;
        // read per request so a config refresh takes effect
        if (!tenants.trustedRealms().contains(tenant)) {
            // the route is not resolved yet at this point; only the path prefix is logged because deeper
            // segments can carry link codes. The realm comes from a token whose signature is not checked yet
            log.info("Bearer token for realm '{}' on {} {} is not in tenants.registrations; rejected with 401",
                    tenant.isEmpty() ? "(none)" : truncate(tenant), request.getRequest().getMethod().name(), pathPrefix(request));
            return Mono.error(invalidToken(INVALID_TENANT));
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
        // only a Bearer token has been verified by Spring Security, so a tenant is never taken from anything else,
        // a bare JWT included
        if (stoken.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            try {
                return getIssuerFromToken(stoken);
            } catch (Exception e) {
                // not reached in practice: Spring Security rejects a malformed Bearer token first
            }
        }
        // only public routes get here: on private routes Spring Security has already rejected such a header.
        // The request is still routed; the path is not logged because public paths can carry link codes
        Route route = request.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        log.info("Public request on route {} ({}) has an Authorization header '{}' that is not a Bearer token; tenant not taken from it",
                route == null ? "unknown" : route.getId(), request.getRequest().getMethod().name(), maskAuthorization(stoken));
        return null;
    }

    /** The first two path segments, e.g. "/api/ipd" for "/api/ipd/v1/x". */
    static String pathPrefix(ServerWebExchange request) {
        String[] segments = request.getRequest().getPath().pathWithinApplication().value().split("/", 4);
        return segments.length > 2 ? "/" + segments[1] + "/" + segments[2] : request.getRequest().getPath().pathWithinApplication().value();
    }

    /** Client supplied values are capped so a long one cannot flood the log. */
    public static String truncate(String value) {
        return value.length() > 64 ? value.substring(0, 64) + "..." : value;
    }

    /** Keeps only the scheme, e.g. "Basic ****", so credentials never reach the log. */
    static String maskAuthorization(String authorization) {
        int space = authorization.indexOf(' ');
        String scheme = space > 0 ? authorization.substring(0, space) : "";
        return (AUTH_SCHEME.matcher(scheme).matches() ? scheme + " " : "") + "****";
    }

    private ReactiveAuthenticationManager fromTenant(String tenant) {
        JwtReactiveAuthenticationManager authenticationManager =
                new JwtReactiveAuthenticationManager(ReactiveJwtDecoders.fromIssuerLocation(keycloakIssuerUri + tenant));
        // rejected tokens (signature, expiry, issuer) keep Spring's 401 invalid_token, as RFC 6750 requires;
        // the decoder reports a failed signing key (JWKS) fetch as IllegalStateException, which Spring Security 6
        // wraps in AuthenticationServiceException (rejected tokens arrive as InvalidBearerTokenException instead)
        return authentication -> authenticationManager.authenticate(authentication)
                .onErrorMap(e -> e instanceof IllegalStateException || e instanceof AuthenticationServiceException,
                        TenantAuthenticationManagerResolver::keycloakUnavailable);
    }

    static OAuth2AuthenticationException invalidToken(String description) {
        return new OAuth2AuthenticationException(new BearerTokenError(BearerTokenErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED, description, null));
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
