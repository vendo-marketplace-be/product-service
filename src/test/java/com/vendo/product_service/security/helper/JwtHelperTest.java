package com.vendo.product_service.security.helper;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.builder.JwtTokenBuilder;
import com.vendo.product_service.security.common.config.JwtProperties;
import com.vendo.product_service.security.common.exception.InvalidTokenException;
import com.vendo.product_service.security.common.helper.JwtHelper;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@ActiveProfiles("test")

public class JwtHelperTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private JwtTokenBuilder tokenFactory;

    private JwtHelper jwtHelper;


    @BeforeEach
    void setup() {
        jwtHelper = new JwtHelper(jwtProperties);
    }

    @Test
    void extractSubject_shouldReturnCorrectSubject() {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        String subject = jwtHelper.extractSubject(token).orElseThrow(() -> new AssertionError("Subject should be present"));

        assertThat(subject).isEqualTo("user-123");
    }

    @Test
    void parseRolesFromToken_shouldReturnCorrectRoles() {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER", "ROLE_ADMIN"));

        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(jwtHelper.extractAllClaims(token));

        assertThat(roles).extracting("authority").containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void parseRolesFromToken_shouldThrowInvalidTokenException_whenTokenWithoutRoles() {
        String tokenWithoutRoles = tokenFactory.generateTokenWithoutRoles("user-123", UserStatus.ACTIVE);

        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () ->
                jwtHelper.parseRolesFromToken(jwtHelper.extractAllClaims(tokenWithoutRoles))
        );
        assertThat(exception.getMessage()).isEqualTo("Invalid roles");
    }

    @Test
    void parseUserStatus_shouldReturnCorrectUserStatus() {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        UserStatus userStatus = jwtHelper.parseUserStatus(jwtHelper.extractAllClaims(token));

        assertThat(userStatus).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void parseUserStatus_shouldThrowInvalidTokenException_whenTokenWithInvalidUserStatus() {
        String tokenWithInvalidStatus = tokenFactory.generateTokenWithInvalidStatus("user-123", List.of("ROLE_USER"));

        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () ->
                jwtHelper.parseUserStatus(jwtHelper.extractAllClaims(tokenWithInvalidStatus)));

        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).isEqualTo("Invalid user status");
    }

    @Test
    void parseSignedClaims_shouldReturnCorrectClaims() {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        Claims claims = jwtHelper.extractAllClaims(token);
        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(claims);
        UserStatus status = jwtHelper.parseUserStatus(claims);

        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo("user-123");
        assertThat(roles).extracting("authority").containsExactly("ROLE_USER");
        assertThat(status).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void parseSignedClaims_shouldThrowExpiredJwtException_whenTokenExpired() {
        String expiredToken = tokenFactory.generateExpiredToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        ExpiredJwtException exception = assertThrows(ExpiredJwtException.class, () ->
                jwtHelper.extractAllClaims(expiredToken)
        );

        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).contains("JWT expired");
    }

    @Test
    void extractClaim_shouldReturnClaimValue() {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

        Claims claims = jwtHelper.extractAllClaims(token);
        UserStatus status = jwtHelper.parseUserStatus(claims);
        String subject = jwtHelper.extractClaim(token, Claims::getSubject)
                .orElseThrow(() -> new AssertionError("Subject should be present"));
        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(claims);

        assertThat(claims).isNotNull();
        assertThat(subject).isEqualTo("user-123");
        assertThat(status).isEqualTo(UserStatus.ACTIVE);
        assertThat(roles).extracting("authority").containsExactlyInAnyOrder("ROLE_USER");
    }

    @Test
    void extractAllClaims_shouldThrowJwtException_whenInvalidFormatToken() {
        JwtException exception = assertThrows(JwtException.class, () ->
                jwtHelper.extractAllClaims(JwtTokenBuilder.INVALID_TOKEN_FORMAT)
        );

        assertThat(exception.getMessage()).isNotBlank();
    }
}
