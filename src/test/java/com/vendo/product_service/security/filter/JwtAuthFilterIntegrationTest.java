package com.vendo.product_service.security.filter;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.common.builder.JwtPayloadBuilder;
import com.vendo.product_service.common.dto.JwtPayload;
import com.vendo.product_service.service.JwtService;
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
import java.util.Map;

import static com.vendo.product_service.service.JwtService.*;
import static com.vendo.security.common.constants.AuthConstants.AUTHORIZATION_HEADER;
import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;
import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;
import static com.vendo.security.common.type.TokenClaim.STATUS_CLAIM;
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
    private JwtService jwtService;

    @Autowired
    private JwtPayloadBuilder jwtPayloadBuilder;

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
                List.of(new SimpleGrantedAuthority(ROLE_USER))
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
    void doFilterInternal_shouldReturnUnauthorized_whenNoToken() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(get("/test/ping"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    void doFilterInternal_shouldPassAuthorization_whenTokenIsValid() throws Exception {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().build();

        String token = jwtService.generateAccessToken(jwtPayload);

        mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + token))
                .andExpect(status().isOk());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutPrefix() throws Exception {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().build();
        String token = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, token))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserBlocked() throws Exception {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.BLOCKED,
                ROLES_CLAIM.getClaim(), List.of(ROLE_USER)
        );
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().claims(claims).build();
        String token = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + token))
                .andExpect(status().isForbidden())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("User is blocked");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenExpired() throws Exception {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().expiration(0).build();
        String expiredToken = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + expiredToken))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutRoles() throws Exception {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE
        );
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().claims(claims).build();
        String tokenWithoutRoles = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + tokenWithoutRoles))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Invalid roles");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenUserStatusMissing() throws Exception {
        Map<String, Object> claims = Map.of(
                ROLES_CLAIM.getClaim(), List.of(ROLE_USER)
        );
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().claims(claims).build();
        String tokenWithoutStatus = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + tokenWithoutStatus))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Invalid user status");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenHasInvalidStatus() throws Exception {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), INVALID_STATUS,
                ROLES_CLAIM.getClaim(), List.of(ROLE_USER)
        );
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().claims(claims).build();
        String tokenWithInvalidStatus = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + tokenWithInvalidStatus))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Invalid user status");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenIsInvalidFormatToken() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + INVALID_TOKEN_FORMAT))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired or invalid");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenHasInvalidSignature() throws Exception {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().key(jwtService.getBadSecretKey()).build();
        String invalidSignedToken = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + invalidSignedToken))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token has expired or invalid");

    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutSubject() throws Exception {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().subject(null).build();
        String tokenWithoutSubject = jwtService.generateAccessToken(jwtPayload);

        MockHttpServletResponse response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION_HEADER, BEARER_PREFIX + tokenWithoutSubject))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();
        String responseContent = response.getContentAsString();

        assertThat(responseContent).isNotBlank();
        assertThat(responseContent).isEqualTo("Token subject missing");
    }
}
