package com.vendo.product_service.builder;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.security.common.config.JwtProperties;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;
import static com.vendo.security.common.type.TokenClaim.STATUS_CLAIM;

@Service
public class JwtTokenBuilder {

    public static final String INVALID_TOKEN_FORMAT = "this.is.not.a.jwt";

    @Autowired
    private JwtProperties jwtProperties;

    @Value("${security.jwt.bad-secret-key}")
    private String BAD_SECRET_KEY;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    private SecretKey getBadSecretKey() {
        return Keys.hmacShaKeyFor(BAD_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(String subject, UserStatus status, List<String> roles) {
        return buildToken(subject, status, roles, getSigningKey());
    }

    public String generateExpiredToken(String subject, UserStatus status, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim(ROLES_CLAIM.getClaim(), roles)
                .claim(STATUS_CLAIM.getClaim(), status)
                .issuedAt(Date.from(now.minus(5, ChronoUnit.MINUTES)))
                .expiration(Date.from(now.minus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenWithoutStatus(String subject, List<String> roles) {
        return buildToken(subject, null, roles, getSigningKey());
    }

    public String generateTokenWithInvalidStatus(String subject, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim(ROLES_CLAIM.getClaim(), roles)
                .claim(STATUS_CLAIM.getClaim(), "INVALID_TOKEN")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenWithInvalidSignature(String subject, UserStatus status, List<String> roles) {
        return buildToken(subject, status, roles, getBadSecretKey());
    }

    public String generateTokenWithoutRoles(String subject, UserStatus status) {
        return buildToken(subject, status, null, getSigningKey());
    }

    public String generateTokenWithoutSubject(UserStatus status, List<String> roles) {
        return buildToken(null, status, roles, getSigningKey());
    }

    public String generateUnsupportedAlgorithmToken(String subject, UserStatus status, List<String> roles) {
        Instant now = Instant.now();

        return Jwts.builder()
                .subject(subject)
                .claim(ROLES_CLAIM.getClaim(), roles)
                .claim(STATUS_CLAIM.getClaim(), status)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .compact();
    }

    //TODO: refactor method and unify the arguments
    private String buildToken(String subject, UserStatus status, List<String> roles, SecretKey key) {
        Instant now = Instant.now();
        JwtBuilder builder = Jwts.builder()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(key, Jwts.SIG.HS256);

        if (subject != null) {
            builder.subject(subject);
        }
        if (roles != null) {
            builder.claim(ROLES_CLAIM.getClaim(), roles);
        }
        if (status != null) {
            builder.claim(STATUS_CLAIM.getClaim(), status);
        }

        return builder.compact();
    }
}
