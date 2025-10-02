package com.vendo.product_service.security.filter;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.builder.JwtTokenBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
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
    private JwtTokenBuilder tokenFactory;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldPassAuthorization_whenUserAlreadyAuthorized() throws Exception {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                "user-123",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        MockHttpServletResponse response = mockMvc.perform(
                        get("/test/ping").with(authentication(authToken))
                )
                .andExpect(status().isOk())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotNull();
        assertThat(responseContent).isEqualTo("pong");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenNoTokenInRequest() throws Exception {

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    void doFilterInternal_shouldPassAuthorization_whenTokenIsValid() throws Exception {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutPrefix() throws Exception {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, token))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired or invalid");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserBlocked() throws Exception {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.BLOCKED, List.of("ROLE_USER"));

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("User is blocked");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenExpired() throws Exception {
        String expiredToken = tokenFactory.generateExpiredToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserStatusMissing() throws Exception {
        String tokenWithoutStatus = tokenFactory.generateTokenWithoutStatus("user-123", List.of("ROLE_USER"));

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + tokenWithoutStatus))
                .andExpect(status().isForbidden())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("User status missing");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenTokenHasInvalidStatus() throws Exception {
        String tokenWithInvalidStatus = tokenFactory.generateTokenWithInvalidStatus("user-123", List.of("ROLE_USER"));

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + tokenWithInvalidStatus))
                .andExpect(status().isForbidden())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Invalid user status");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenIsInvalidFormatToken() throws Exception {
        String malformedToken = tokenFactory.generateInvalidFormatToken();

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + malformedToken))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired or invalid");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenHasInvalidSignature() throws Exception {
        String invalidSignedToken = tokenFactory.generateTokenWithInvalidSignature("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, "Bearer " + invalidSignedToken))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired or invalid");

    }
}
