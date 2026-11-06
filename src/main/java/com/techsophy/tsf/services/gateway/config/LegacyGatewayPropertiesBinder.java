package com.techsophy.tsf.services.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.config.GlobalCorsProperties;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import java.util.Map;

/**
 * Spring Cloud Gateway 5 only reads spring.cloud.gateway.server.webflux.*; the routes, default filters,
 * CORS and HTTP client settings of this gateway (including those served by the config server) still use
 * spring.cloud.gateway.*. When nothing is configured under the new prefix, the old one is bound instead.
 */
@Slf4j
@Component
public class LegacyGatewayPropertiesBinder implements BeanPostProcessor, EnvironmentAware
{
    static final String LEGACY_PREFIX = "spring.cloud.gateway";
    static final String PREFIX = "spring.cloud.gateway.server.webflux";

    private Environment environment;

    @Override
    public void setEnvironment(Environment environment)
    {
        this.environment = environment;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName)
    {
        if (bean instanceof GatewayProperties)
        {
            bindLegacy(bean, "");
        }
        else if (bean instanceof GlobalCorsProperties)
        {
            bindLegacy(bean, ".globalcors");
        }
        else if (bean instanceof HttpClientProperties)
        {
            bindLegacy(bean, ".httpclient");
        }
        return bean;
    }

    private void bindLegacy(Object bean, String suffix)
    {
        Binder binder = Binder.get(environment);
        boolean configured = binder.bind(PREFIX + suffix, Bindable.mapOf(String.class, Object.class))
                .map(Map::size).orElse(0) > 0;
        if (!configured && binder.bind(LEGACY_PREFIX + suffix, Bindable.ofInstance(bean)).isBound())
        {
            log.warn("Using legacy '{}' properties; move them under '{}'", LEGACY_PREFIX + suffix, PREFIX + suffix);
        }
    }
}
