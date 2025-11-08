package com.vendo.product_service.common.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Profile({"dev", "prod"})
public class StartupRunnerConfig implements CommandLineRunner {

    @Value("${server.url}")
    private String SERVER_URL;

    private static final String SWAGGER_UI_URL_TEMPLATE = "%s/swagger-ui/index.html";

    @Override
    public void run(String... args) {
        log.info("Swagger UI: {}", SWAGGER_UI_URL_TEMPLATE.formatted(SERVER_URL));
    }
}
