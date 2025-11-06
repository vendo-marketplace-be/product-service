package com.vendo.product_service.security.filter;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.security.common.helper.JwtHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class JwtAuthFilterIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtHelper jwtHelper;

    @BeforeEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldPassAuthorization_whenUserAlreadyAuthorized() throws Exception {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                "existingUser",
                null,
                null);

        MockHttpServletResponse response = mockMvc.perform(
                        get("/test/ping").with(authentication(authToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        String responseContent = response.getContentAsString();
        assertThat(responseContent).isEqualTo("pong");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenNoTokenInRequest() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(get("/test/ping"))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    void doFilterInternal_shouldPassFilter_whenTokenIsValid() throws Exception {
        String token = JwtTestHelper.createToken(
                jwtHelper.getSignInKey(),
                "user@example.com",
                UserStatus.ACTIVE);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        assertThat(response.getContentAsString()).isEqualTo("pong");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenIsExpired() throws Exception {
        String expiredToken = JwtTestHelper.createExpiredToken(
                jwtHelper.getSignInKey(),
                "user@example.com",
                UserStatus.ACTIVE);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token expired");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserIsBlocked() throws Exception {
        String blockedToken = JwtTestHelper.createToken(
                jwtHelper.getSignInKey(),
                "user@example.com",
                UserStatus.BLOCKED);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, "Bearer " + blockedToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(response.getContentAsString()).isEqualTo("User is unactive");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserIsIncomplete() throws Exception {
        String blockedToken = JwtTestHelper.createToken(
                jwtHelper.getSignInKey(),
                "user@example.com",
                UserStatus.INCOMPLETE);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, "Bearer " + blockedToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(response.getContentAsString()).isEqualTo("User is unactive");
    }
}
