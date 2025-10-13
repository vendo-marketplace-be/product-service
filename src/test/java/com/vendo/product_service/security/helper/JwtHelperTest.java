package com.vendo.product_service.security.helper;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.common.builder.JwtPayloadBuilder;
import com.vendo.product_service.common.dto.JwtPayload;
import com.vendo.product_service.security.common.config.JwtProperties;
import com.vendo.product_service.security.common.exception.InvalidTokenException;
import com.vendo.product_service.security.common.helper.JwtHelper;
import com.vendo.product_service.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;

import static com.vendo.product_service.service.JwtService.*;
import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;
import static com.vendo.security.common.type.TokenClaim.STATUS_CLAIM;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@ActiveProfiles("test")

public class JwtHelperTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtPayloadBuilder jwtPayloadBuilder;

    private JwtHelper jwtHelper;

    @BeforeEach
    void setup() {
        jwtHelper = new JwtHelper(jwtProperties);
    }

    @Test
    void extractSubject_shouldExtractCorrectSubject() {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().build();
        String token = jwtService.generateAccessToken(jwtPayload);

        String subject = jwtHelper.extractSubject(token).orElseThrow(() -> new AssertionError("Subject should be present"));

        assertThat(subject).isNotBlank();
        assertThat(subject).isEqualTo(jwtPayload.getSubject());
    }

    @Test
    void parseRoleFromToken_shouldExtractCorrectRole() {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().build();
        String token = jwtService.generateAccessToken(jwtPayload);

        List<SimpleGrantedAuthority> roles = jwtHelper.parseRoles(jwtHelper.extractAllClaims(token));

        assertThat(roles).isNotNull();
        assertThat(roles.size()).isEqualTo(1);
        assertThat(roles).contains(new SimpleGrantedAuthority(ROLE_USER));
    }

    @Test
    void parseRolesFromToken_shouldThrowInvalidTokenException_whenTokenWithoutRoles() {
        Map<String, Object> claims = Map.of(STATUS_CLAIM.getClaim(), UserStatus.ACTIVE);
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().claims(claims).build();
        String tokenWithoutRoles = jwtService.generateAccessToken(jwtPayload);

        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () ->
                jwtHelper.parseRoles(jwtHelper.extractAllClaims(tokenWithoutRoles))
        );

        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Invalid roles");
    }

    @Test
    void parseUserStatus_shouldExtractCorrectUserStatus() {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().build();
        String token = jwtService.generateAccessToken(jwtPayload);

        UserStatus userStatus = jwtHelper.parseUserStatus(jwtHelper.extractAllClaims(token));

        assertThat(userStatus).isNotNull();
        assertThat(userStatus).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void parseUserStatus_shouldThrowInvalidTokenException_whenTokenWithInvalidUserStatus() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), INVALID_STATUS,
                ROLES_CLAIM.getClaim(), List.of(ROLE_USER)
        );
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().claims(claims).build();
        String tokenWithInvalidStatus = jwtService.generateAccessToken(jwtPayload);

        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () ->
                jwtHelper.parseUserStatus(jwtHelper.extractAllClaims(tokenWithInvalidStatus)));

        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).isEqualTo("Invalid user status");
    }

    @Test
    void parseSignedClaims_shouldExtractCorrectClaims() {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().build();
        String token = jwtService.generateAccessToken(jwtPayload);

        Claims extractedAllClaimsclaims = jwtHelper.extractAllClaims(token);
        List<SimpleGrantedAuthority> roles = jwtHelper.parseRoles(extractedAllClaimsclaims);
        UserStatus status = jwtHelper.parseUserStatus(extractedAllClaimsclaims);

        assertThat(extractedAllClaimsclaims).isNotNull();
        assertThat(status).isNotNull();
        assertThat(roles).isNotNull();
        assertThat(extractedAllClaimsclaims.getSubject()).isEqualTo(jwtPayload.getSubject());
        assertThat(roles).contains(new SimpleGrantedAuthority(ROLE_USER));
        assertThat(status).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void parseSignedClaims_shouldThrowExpiredJwtException_whenTokenExpired() {
        JwtPayload jwtPayload = jwtPayloadBuilder.buildValidUserJwtPayload().expiration(0).build();
        String expiredToken = jwtService.generateAccessToken(jwtPayload);

        ExpiredJwtException exception = assertThrows(ExpiredJwtException.class, () ->
                jwtHelper.extractAllClaims(expiredToken)
        );

        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).contains("JWT expired");
    }

    @Test
    void extractAllClaims_shouldThrowJwtException_whenInvalidFormatToken() {
        JwtException exception = assertThrows(JwtException.class, () ->
                jwtHelper.extractAllClaims(INVALID_TOKEN_FORMAT)
        );

        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).contains("Invalid compact JWT string");
    }
}
