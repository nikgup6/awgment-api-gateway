package com.techsophy.tsf.services.gateway.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import java.util.List;

class SecurityConfigTest
{
    @Test
    void middleDoubleWildcardIsRewrittenToSingleSegmentTest()
    {
        Assertions.assertArrayEquals(new String[]{"/*/config-server/**", "/*/a/*/b/**", "/api/public/**"},
                SecurityConfig.toPathPatterns(List.of("/**/config-server/**", "/**/a/**/b/**", "/api/public/**")));
    }

    @Test
    void rewrittenPatternMatchesLikeSpring5Test()
    {
        // expected values recorded from Spring 5.2.9 PathPatternParser parsing "/**/config-server/**"
        PathPattern pattern = PathPatternParser.defaultInstance.parse(SecurityConfig.toPathPatterns(List.of("/**/config-server/**"))[0]);
        Assertions.assertTrue(pattern.matches(PathContainer.parsePath("/api/config-server/x")));
        Assertions.assertTrue(pattern.matches(PathContainer.parsePath("/api/config-server")));
        Assertions.assertTrue(pattern.matches(PathContainer.parsePath("/x/config-server/a/b/c")));
        Assertions.assertFalse(pattern.matches(PathContainer.parsePath("/config-server/x")));
        Assertions.assertFalse(pattern.matches(PathContainer.parsePath("/a/b/config-server/x")));
        Assertions.assertFalse(pattern.matches(PathContainer.parsePath("/api/config-serverx/y")));
        Assertions.assertFalse(pattern.matches(PathContainer.parsePath("/api/form/x")));
    }
}
