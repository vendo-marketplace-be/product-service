package com.vendo.product_service.security.filter;

import com.vendo.security.AntPathResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;

@Component
public class ProductAntPathResolver implements AntPathResolver {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public static final String[] PERMITTED_PATHS = new String[] {
            "/swagger-ui/**",
            "/v3/api-docs/**",
    };

    @Override
    public boolean isPermittedPath(String path) {
        return Arrays.stream(PERMITTED_PATHS).anyMatch(pr -> antPathMatcher.match(pr, path));
    }
}
