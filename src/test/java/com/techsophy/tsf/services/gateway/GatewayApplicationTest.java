package com.techsophy.tsf.services.gateway;

import com.techsophy.tsf.services.gateway.exception.InvalidInputException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;

@ExtendWith(MockitoExtension.class)
class GatewayApplicationTest
{
    @Mock
    SwaggerUiConfigProperties swaggerUiConfigProperties;
    @Mock
    RouteDefinitionLocator routeDefinitionLocator;
    @Mock
    RouteDefinition routeDefinition;

    @Test
    void apisLocatorNullTest()
    {
        Assertions.assertThrows(InvalidInputException.class,()->GatewayApplication.apis(null,null,null));
    }
}
