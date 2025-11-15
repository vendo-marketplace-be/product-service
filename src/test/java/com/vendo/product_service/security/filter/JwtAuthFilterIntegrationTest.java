package com.vendo.product_service.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.common.exception.ExceptionResponse;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.common.builder.JwtTokenDataBuilder;
import com.vendo.product_service.security.common.helper.JwtHelper;
import com.vendo.security.common.exception.AccessDeniedException;
import com.vendo.security.common.exception.InvalidTokenException;
import com.vendo.security.common.type.TokenClaim;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Date;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;
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

    @Autowired
    private ObjectMapper objectMapper;

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
                "existingUser",
                null,
                null);

        MockHttpServletResponse response = mockMvc.perform(
                        get("/test/ping").with(authentication(authToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        String responseContent = response.getContentAsString();
        assertThat(responseContent).isNotBlank();
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
        ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);

        assertThat(exceptionResponse.message()).isEqualTo("Invalid token.");
        assertThat(exceptionResponse.code()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.path()).isEqualTo("/test/ping");
        assertThat(exceptionResponse.type()).isEqualTo(InvalidTokenException.class.getSimpleName());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutBearerPrefix() throws Exception {
        String token = JwtTokenDataBuilder.buildTokenWithRequiredFields(jwtHelper.getSignInKey())
                .compact();

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, token))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse();

        String responseContent = response.getContentAsString();
        assertThat(responseContent).isNotBlank();
        ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);

        assertThat(exceptionResponse.message()).isEqualTo("Invalid token.");
        assertThat(exceptionResponse.code()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.path()).isEqualTo("/test/ping");
        assertThat(exceptionResponse.type()).isEqualTo(InvalidTokenException.class.getSimpleName());
    }

    @Test
    void doFilterInternal_shouldPassFilter_whenTokenIsValid() throws Exception {
        String token = JwtTokenDataBuilder.buildTokenWithRequiredFields(jwtHelper.getSignInKey())
                .compact();

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, BEARER_PREFIX + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        assertThat(response.getContentAsString()).isEqualTo("pong");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenIsExpired() throws Exception {
        String expiredToken = JwtTokenDataBuilder.buildTokenWithRequiredFields(jwtHelper.getSignInKey())
                .expiration(new Date(System.currentTimeMillis() - 1))
                .compact();

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, BEARER_PREFIX + expiredToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse();

        String responseContent = response.getContentAsString();
        assertThat(responseContent).isNotBlank();
        ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);

        assertThat(exceptionResponse.message()).isEqualTo("Token has expired.");
        assertThat(exceptionResponse.code()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.path()).isEqualTo("/test/ping");
        assertThat(exceptionResponse.type()).isEqualTo(ExpiredJwtException.class.getSimpleName());
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserIsBlocked() throws Exception {
        String blockedToken = JwtTokenDataBuilder.buildTokenWithRequiredFields(jwtHelper.getSignInKey())
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), UserStatus.BLOCKED.name())
                .compact();

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, BEARER_PREFIX + blockedToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse();

        String responseContent = response.getContentAsString();
        assertThat(responseContent).isNotBlank();
        ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);

        assertThat(exceptionResponse.message()).isEqualTo("User is unactive.");
        assertThat(exceptionResponse.code()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(exceptionResponse.path()).isEqualTo("/test/ping");
        assertThat(exceptionResponse.type()).isEqualTo(AccessDeniedException.class.getSimpleName());
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserIsIncomplete() throws Exception {
        String incompleteToken = JwtTokenDataBuilder.buildTokenWithRequiredFields(jwtHelper.getSignInKey())
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), UserStatus.INCOMPLETE.name())
                .compact();

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping")
                        .header(AUTHORIZATION, BEARER_PREFIX + incompleteToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse();

        String responseContent = response.getContentAsString();
        assertThat(responseContent).isNotBlank();
        ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);

        assertThat(exceptionResponse.message()).isEqualTo("User is unactive.");
        assertThat(exceptionResponse.code()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(exceptionResponse.path()).isEqualTo("/test/ping");
        assertThat(exceptionResponse.type()).isEqualTo(AccessDeniedException.class.getSimpleName());
    }
}
