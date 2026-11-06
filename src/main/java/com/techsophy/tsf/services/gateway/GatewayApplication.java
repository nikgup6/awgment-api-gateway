package com.techsophy.tsf.services.gateway;

import com.techsophy.tsf.services.gateway.exception.InvalidInputException;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springdoc.core.properties.AbstractSwaggerUiConfigProperties.SwaggerUrl;
import org.springdoc.core.properties.SpringDocConfigProperties;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.BASE_URL;

@SpringBootApplication
@RestController
@RequestMapping(BASE_URL)
public class GatewayApplication {

    public static void main(String[] args) {

        SpringApplication.run(GatewayApplication.class, args);
    }

    @Bean
    @Lazy(false)
    public static List<GroupedOpenApi> apis(SwaggerUiConfigProperties swaggerUiConfigProperties, SpringDocConfigProperties springDocConfigProperties,
                                           RouteDefinitionLocator locator) {
        if (null == locator) {
            throw new InvalidInputException("invalid");
        }
        List<GroupedOpenApi> groups = new ArrayList<>();
        List<RouteDefinition> definitions = locator.getRouteDefinitions().collectList().block();
        if (null == definitions) {
            throw new InvalidInputException("invalid");
        }
        // springdoc 2 no longer exposes SwaggerUiConfigParameters as a bean; register each group's api-docs URL
        // (the same "<api-docs path>/<group>" URL that addGroup produced) on the Swagger UI properties instead
        Set<SwaggerUrl> urls = swaggerUiConfigProperties.getUrls() == null ? new LinkedHashSet<>() : new LinkedHashSet<>(swaggerUiConfigProperties.getUrls());
        String apiDocsPath = springDocConfigProperties.getApiDocs().getPath();
        definitions.stream().filter(routeDefinition -> routeDefinition.getId().matches(".*-service")).forEach(routeDefinition -> {
            String name = routeDefinition.getId().replace("-service", "");
            urls.add(new SwaggerUrl(name, apiDocsPath + "/" + name, name));
            GroupedOpenApi.builder().pathsToMatch("/" + name + "/**").group(name).build();
        });
        swaggerUiConfigProperties.setUrls(urls);
        return groups;
    }

    @Bean
    public OpenAPI customOpenAPI(@Value("${springdoc.version}") String appVersion) {
        return new OpenAPI()
                .components(new Components())
                .info(new io.swagger.v3.oas.models.info.Info().title("Gateway API").version(appVersion)
                        .license(new License().name("Apache 2.0").url("http://springdoc.org")));
    }
}
