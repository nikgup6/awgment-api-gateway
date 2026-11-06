package com.techsophy.tsf.services.gateway.filter;

import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.X_CORRELATIONID;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.X_TENANT;
import static com.techsophy.tsf.services.gateway.constants.GatewayTestConstants.*;

@ExtendWith(MockitoExtension.class)
class MultitenancyFilterTest
{
    @Test
    void filterWithNullTenantTest()
    {
        MultiTenancyFilter multiTenancyFilter=new MultiTenancyFilter(tenants());
        LinkedMultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        MockServerWebExchange webExchange = MockServerWebExchange
                .builder(MockServerHttpRequest
                        .get(TEST_URL)
                        .headers(new HttpHeaders(headers))
                        .build())
                .build();
        GatewayFilterChain gatewayFilterChain = (exchange) -> {
            headers.set(X_TENANT, TECHSOPHY_PLATFORM);
            return ServerResponse.ok()
                    .headers(h -> h.addAll(exchange.getResponse().getHeaders()))
                    .bodyValue(RESPONSE_BODY)
                    .then();
        };
        Mono<Void> result=multiTenancyFilter.filter(webExchange, gatewayFilterChain);
        StepVerifier.create(result)
                .expectSubscription()
                .expectComplete()
                .verify();
        MockServerHttpResponse response=webExchange.getResponse();
        HttpHeaders httpHeadersResponse=response.getHeaders();
        Assertions.assertNull(httpHeadersResponse.get(X_TENANT));
        Assertions.assertNotNull(httpHeadersResponse.get(X_CORRELATIONID));
    }

    @Test
    void filterWithDefaultHeaderTest()
    {
        MultiTenancyFilter multiTenancyFilter=new MultiTenancyFilter(tenants());
        LinkedMultiValueMap<String, String> headers = new LinkedMultiValueMap<>(Map.of(X_TENANT, List.of(TECHSOPHY_PLATFORM)));
        headers.put(AUTHORIZATION,List.of(BEARER_TOKEN));
        MockServerWebExchange webExchange = MockServerWebExchange
                .builder(MockServerHttpRequest
                .get(TEST_URL)
                        .headers(new HttpHeaders(headers))
                        .build())
                .build();
        GatewayFilterChain gatewayFilterChain = (exchange) -> {
            headers.set(X_TENANT, TECHSOPHY_PLATFORM);
            return ServerResponse.ok()
                    .headers(h -> h.addAll(exchange.getResponse().getHeaders()))
                    .bodyValue(RESPONSE_BODY)
                    .then();
        };
        Mono<Void> result=multiTenancyFilter.filter(webExchange, gatewayFilterChain);
        StepVerifier.create(result)
                .expectSubscription()
                .expectComplete()
                .verify();
        MockServerHttpResponse response=webExchange.getResponse();
        HttpHeaders httpHeadersResponse=response.getHeaders();
        Assertions.assertEquals(TECHSOPHY_PLATFORM, httpHeadersResponse.getFirst(X_TENANT));
        Assertions.assertNotNull(httpHeadersResponse.get(X_CORRELATIONID));
    }

    @Test
    void filterWithNewHeaderTest()
    {
        MultiTenancyFilter multiTenancyFilter=new MultiTenancyFilter(tenants());
        LinkedMultiValueMap<String, String> headers = new LinkedMultiValueMap<>(Map.of(X_TENANT, List.of(TESTING_TENANT)));
        MockServerWebExchange webExchange = MockServerWebExchange
                .builder(MockServerHttpRequest
                        .get(TEST_URL)
                        .headers(new HttpHeaders(headers))
                        .build())
                .build();
        GatewayFilterChain gatewayFilterChain = (exchange) -> {
            headers.set(X_TENANT,TESTING_TENANT);
            return ServerResponse.ok()
                    .headers(h -> h.addAll(exchange.getResponse().getHeaders()))
                    .bodyValue(RESPONSE_BODY)
                    .then();
        };
        Mono<Void> result=multiTenancyFilter.filter(webExchange, gatewayFilterChain);
        StepVerifier.create(result)
                .expectSubscription()
                .expectComplete()
                .verify();
        MockServerHttpResponse response=webExchange.getResponse();
        HttpHeaders httpHeadersResponse=response.getHeaders();
        Assertions.assertEquals(TESTING_TENANT, httpHeadersResponse.getFirst(X_TENANT));
        Assertions.assertNotNull(httpHeadersResponse.get(X_CORRELATIONID));
    }

    @Test
    void filterWithUnlistedHeaderTest()
    {
        MultiTenancyFilter multiTenancyFilter=new MultiTenancyFilter(tenants());
        MockServerWebExchange webExchange = MockServerWebExchange
                .from(MockServerHttpRequest.get(TEST_URL).header(X_TENANT, "unknown-realm"));
        AtomicBoolean routed = new AtomicBoolean();
        GatewayFilterChain gatewayFilterChain = exchange -> {
            routed.set(true);
            return Mono.empty();
        };
        StepVerifier.create(multiTenancyFilter.filter(webExchange, gatewayFilterChain))
                .expectErrorSatisfies(e -> Assertions.assertEquals(HttpStatus.BAD_REQUEST, ((ResponseStatusException) e).getStatusCode()))
                .verify();
        Assertions.assertFalse(routed.get());
    }

    @Test
    void filterBearerTenantOverridesUnlistedHeaderTest()
    {
        // the tenant from a Bearer token wins, so an unlisted X-Tenant sent alongside it is replaced, not rejected
        MultiTenancyFilter multiTenancyFilter=new MultiTenancyFilter(tenants());
        MockServerWebExchange webExchange = MockServerWebExchange
                .from(MockServerHttpRequest.get(TEST_URL).header(X_TENANT, "unknown-realm").header(AUTHORIZATION, BEARER_TOKEN));
        GatewayFilterChain gatewayFilterChain = exchange -> {
            Assertions.assertEquals(TECHSOPHY_PLATFORM, exchange.getRequest().getHeaders().getFirst(X_TENANT));
            return Mono.empty();
        };
        StepVerifier.create(multiTenancyFilter.filter(webExchange, gatewayFilterChain)).verifyComplete();
        Assertions.assertEquals(TECHSOPHY_PLATFORM, webExchange.getResponse().getHeaders().getFirst(X_TENANT));
    }

    private static TenantRegistration tenants()
    {
        TenantRegistration tenantRegistration = new TenantRegistration();
        tenantRegistration.setRegistrations(List.of(TECHSOPHY_PLATFORM + "," + TESTING_TENANT));
        return tenantRegistration;
    }
}
