package com.techsophy.tsf.services.gateway.filter;

import com.techsophy.idgenerator.IdGeneratorImpl;
import com.techsophy.tsf.services.gateway.config.TenantAuthenticationManagerResolver;
import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.INVALID_TENANT;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.X_CORRELATIONID;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.X_TENANT;

@Component
@RequiredArgsConstructor
public class MultiTenancyFilter implements GlobalFilter
{
    private final Logger logger = LoggerFactory.getLogger(MultiTenancyFilter.class);
    private final IdGeneratorImpl idGenerator=new IdGeneratorImpl();
    private final TenantRegistration tenants;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain)
    {
        String jwtTenant= TenantAuthenticationManagerResolver.toTenant(exchange);
        String tenant = jwtTenant==null?exchange.getRequest().getHeaders().getFirst(X_TENANT):jwtTenant;
        // a tenant from a Bearer token was already checked by Spring Security; one sent by the client in X-Tenant
        // (public routes, browser sessions) must also be a realm in tenants.registrations
        if (jwtTenant == null && tenant != null && !tenants.trustedRealms().contains(tenant))
        {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            logger.info("Request on route {} ({}) has X-Tenant '{}' that is not in tenants.registrations; rejected with 400",
                    route == null ? "unknown" : route.getId(), exchange.getRequest().getMethod().name(),
                    TenantAuthenticationManagerResolver.truncate(tenant));
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, INVALID_TENANT));
        }
        String correlationId=exchange.getRequest().getHeaders().getFirst(X_CORRELATIONID);
        correlationId=correlationId==null?String.valueOf(idGenerator.nextId()):correlationId;
        ServerHttpRequest.Builder builder=exchange.getRequest()
                .mutate()
                .header(X_CORRELATIONID,correlationId);
        ServerHttpRequest request;
        if(tenant!=null)
        {
            builder=builder.header(X_TENANT,tenant);
        }
        request=builder.build();
        ServerWebExchange modifiedWebExchange=exchange.mutate().request(request).build();
        logger.info("Global Pre Filter executed");
        String finalCorrelationId = correlationId;
        return chain.filter(modifiedWebExchange).then(Mono.fromRunnable(()->{
            ServerHttpResponse serverHttpResponse=modifiedWebExchange.getResponse();
            HttpHeaders httpHeaders=serverHttpResponse.getHeaders();
            if(tenant!=null)
            {
                httpHeaders.set(X_TENANT,tenant);
            }
            httpHeaders.set(X_CORRELATIONID, finalCorrelationId);
        }));
    }
}
