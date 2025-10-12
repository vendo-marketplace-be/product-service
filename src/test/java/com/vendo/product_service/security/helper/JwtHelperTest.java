package com.vendo.product_service.security.helper;

import com.vendo.domain.user.common.type.UserStatus;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;

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
    private JwtService tokenFactory;

    private JwtHelper jwtHelper;

    @Value("${security.jwt.expirationMillis}")
    private int EXPIRATION_TIME;

    @BeforeEach
    void setup() {
        jwtHelper = new JwtHelper(jwtProperties);
    }

    @Test
    void extractSubject_shouldReturnCorrectSubject() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE,
                ROLES_CLAIM.getClaim(), List.of("ROLE_USER")
        );
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String token = tokenFactory.generateAccessToken(payload);

        String subject = jwtHelper.extractSubject(token).orElseThrow(() -> new AssertionError("Subject should be present"));

        assertThat(subject).isEqualTo("user-123");
    }

    @Test
    void parseRolesFromToken_shouldReturnCorrectRoles() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE,
                ROLES_CLAIM.getClaim(), List.of("ROLE_USER", "ROLE_ADMIN")
        );
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String token = tokenFactory.generateAccessToken(payload);

        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(jwtHelper.extractAllClaims(token));

        assertThat(roles).extracting("authority").containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void parseRolesFromToken_shouldThrowInvalidTokenException_whenTokenWithoutRoles() {
        Map<String, Object> claims = Map.of(STATUS_CLAIM.getClaim(), UserStatus.ACTIVE);
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String tokenWithoutRoles = tokenFactory.generateAccessToken(payload);

        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () ->
                jwtHelper.parseRolesFromToken(jwtHelper.extractAllClaims(tokenWithoutRoles))
        );
        assertThat(exception.getMessage()).isEqualTo("Invalid roles");
    }

    @Test
    void parseUserStatus_shouldReturnCorrectUserStatus() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE,
                ROLES_CLAIM.getClaim(), List.of("ROLE_USER")
        );
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String token = tokenFactory.generateAccessToken(payload);

        UserStatus userStatus = jwtHelper.parseUserStatus(jwtHelper.extractAllClaims(token));

        assertThat(userStatus).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void parseUserStatus_shouldThrowInvalidTokenException_whenTokenWithInvalidUserStatus() {
        Map<String, Object> claims = Map.of(ROLES_CLAIM.getClaim(), List.of("ROLE_USER"));
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String tokenWithInvalidStatus = tokenFactory.generateAccessToken(payload);

        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () ->
                jwtHelper.parseUserStatus(jwtHelper.extractAllClaims(tokenWithInvalidStatus)));

        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).isEqualTo("Invalid user status");
    }

    @Test
    void parseSignedClaims_shouldReturnCorrectClaims() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE,
                ROLES_CLAIM.getClaim(), List.of("ROLE_USER")
        );
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String token = tokenFactory.generateAccessToken(payload);

        Claims extractedAllClaimsclaims = jwtHelper.extractAllClaims(token);
        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(extractedAllClaimsclaims);
        UserStatus status = jwtHelper.parseUserStatus(extractedAllClaimsclaims);

        assertThat(extractedAllClaimsclaims).isNotNull();
        assertThat(extractedAllClaimsclaims.getSubject()).isEqualTo("user-123");
        assertThat(roles).extracting("authority").containsExactly("ROLE_USER");
        assertThat(status).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void parseSignedClaims_shouldThrowExpiredJwtException_whenTokenExpired() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE,
                ROLES_CLAIM.getClaim(), List.of("ROLE_USER")
        );
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(0)
                .key(tokenFactory.getSecretKey())
                .build();
        String expiredToken = tokenFactory.generateAccessToken(payload);

        ExpiredJwtException exception = assertThrows(ExpiredJwtException.class, () ->
                jwtHelper.extractAllClaims(expiredToken)
        );

        assertThat(exception.getMessage()).isNotBlank();
        assertThat(exception.getMessage()).contains("JWT expired");
    }

    @Test
    void extractClaim_shouldReturnClaimValue() {
        Map<String, Object> claims = Map.of(
                STATUS_CLAIM.getClaim(), UserStatus.ACTIVE,
                ROLES_CLAIM.getClaim(), List.of("ROLE_USER")
        );
        JwtPayload payload = JwtPayload.builder()
                .subject("user-123")
                .claims(claims)
                .expiration(EXPIRATION_TIME)
                .key(tokenFactory.getSecretKey())
                .build();
        String token = tokenFactory.generateAccessToken(payload);

        Claims extractedAllClaims = jwtHelper.extractAllClaims(token);
        UserStatus status = jwtHelper.parseUserStatus(extractedAllClaims);
        String subject = jwtHelper.extractClaim(token, Claims::getSubject)
                .orElseThrow(() -> new AssertionError("Subject should be present"));
        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(extractedAllClaims);

        assertThat(extractedAllClaims).isNotNull();
        assertThat(subject).isEqualTo("user-123");
        assertThat(status).isEqualTo(UserStatus.ACTIVE);
        assertThat(roles).extracting("authority").containsExactlyInAnyOrder("ROLE_USER");
    }

    @Test
    void extractAllClaims_shouldThrowJwtException_whenInvalidFormatToken() {
        JwtException exception = assertThrows(JwtException.class, () ->
                jwtHelper.extractAllClaims(JwtService.INVALID_TOKEN_FORMAT)
        );

        assertThat(exception.getMessage()).isNotBlank();
    }
}
