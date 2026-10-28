package com.techsophy.tsf.services.gateway.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class GatewayConstants
{
    public static final String BEARER = "Bearer ";
    public static final String BASE_URL= "/api";
    public static final String TEST_ACTIVE_PROFILE="test";
    public static final String X_TENANT="X-Tenant";
    public static final String X_CORRELATIONID="X-CorrelationId";
    public static final String QUERY_PARAM_TENANT="_tenant";
    public static final String REALMS="realms/";
    public static final String MALFORMED_TOKEN="Malformed token";
    public static final String INVALID_TOKEN="Invalid token";
    public static final String INVALID_TENANT="Invalid tenant";
    public static final String KEYCLOAK_UNAVAILABLE="Keycloak unavailable";
}
