package com.techsophy.tsf.services.gateway.config;

import com.nimbusds.jwt.JWTParser;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.text.ParseException;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.BEARER_SCHEME_MISSING;

/**
 * Spring's bearer token converter, except that a JWT sent without the "Bearer" scheme is rejected with
 * 401 invalid_token on every route, public ones included, instead of being treated as no credentials.
 */
public class StrictBearerTokenConverter implements ServerAuthenticationConverter
{
    private final ServerBearerTokenAuthenticationConverter delegate = new ServerBearerTokenAuthenticationConverter();

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange)
    {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && isBareJwt(authorization))
        {
            return Mono.error(TenantAuthenticationManagerResolver.invalidToken(BEARER_SCHEME_MISSING));
        }
        return delegate.convert(exchange);
    }

    static boolean isBareJwt(String authorization)
    {
        if (authorization.isBlank() || authorization.chars().anyMatch(Character::isWhitespace))
        {
            return false;
        }
        try
        {
            JWTParser.parse(authorization);
            return true;
        }
        catch (ParseException e)
        {
            return false;
        }
    }
}
