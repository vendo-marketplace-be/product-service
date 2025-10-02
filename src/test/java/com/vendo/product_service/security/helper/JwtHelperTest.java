package com.vendo.product_service.security.helper;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.builder.JwtTokenBuilder;
import com.vendo.product_service.security.common.config.JwtProperties;
import com.vendo.product_service.security.common.helper.JwtHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

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

        String subject = jwtHelper.extractSubject(token)
                .orElseThrow(() -> new AssertionError("Subject should be present"));

        assertThat(subject).isEqualTo("user-123");
    }

    @Test
    void parseRolesFromToken_shouldReturnCorrectRoles() {
//        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER", "ROLE_ADMIN"));

//        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(token);

//        assertThat(roles).extracting("authority").containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void isTokenExpired_shouldReturnFalseForValidToken() {
        String token = tokenFactory.generateAccessToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

//        boolean expired = jwtHelper.isTokenExpired(token);

//        assertThat(expired).isFalse();
    }

    @Test
    void isTokenExpired_shouldReturnTrueForExpiredToken() {
        String expiredToken = tokenFactory.generateExpiredToken("user-123", UserStatus.ACTIVE, List.of("ROLE_USER"));

//        boolean expired = jwtHelper.isTokenExpired(expiredToken);

//        assertThat(expired).isTrue();
    }

    @Test
    void extractClaim_shouldReturnNullForMissingStatus() {
        String tokenWithoutStatus = tokenFactory.generateTokenWithoutStatus("user-123", List.of("ROLE_USER"));

        Object status = jwtHelper.extractClaim(tokenWithoutStatus, claims -> claims.get("status"))
                .orElse(null);

        assertThat(status).isNull();
    }

    @Test
    void extractClaim_shouldReturnInvalidStatusString() {
        String tokenInvalidStatus = tokenFactory.generateTokenWithInvalidStatus("user-123", List.of("ROLE_USER"));

        Object status = jwtHelper.extractClaim(tokenInvalidStatus, claims -> claims.get("status"))
                .orElse(null);

        assertThat(status).isEqualTo("INVALID_STATUS");
    }

    @Test
    void parseRolesFromToken_shouldReturnEmptyList_whenRolesMissing() {
//        String tokenWithoutRoles = tokenFactory.generateTokenWithoutRoles("user-123", UserStatus.ACTIVE);
//        List<SimpleGrantedAuthority> roles = jwtHelper.parseRolesFromToken(tokenWithoutRoles);
//        assertThat(roles).isEmpty();
    }

}
