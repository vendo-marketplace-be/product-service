package com.vendo.product_service.builder;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.security.common.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static com.vendo.security.common.type.TokenClaim.STATUS_CLAIM;

@Component
public class JwtTokenBuilder {

    @Autowired
    private JwtProperties jwtProperties;

    @Value("security.jwt.bad-secret-key")
    private String BAD_SECRET_KEY;


    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    private SecretKey getBadSecretKey() {
        return Keys.hmacShaKeyFor(BAD_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(String subject, UserStatus status, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .claim(STATUS_CLAIM.getClaim(), status)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateExpiredToken(String subject, UserStatus status, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .claim(STATUS_CLAIM.getClaim(), status)
                .issuedAt(Date.from(now.minus(5, ChronoUnit.MINUTES)))
                .expiration(Date.from(now.minus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenWithoutStatus(String subject, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenWithInvalidStatus(String subject, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .claim("status", "INVALID_STATUS")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenWithInvalidSignature(String subject, UserStatus status, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .claim(STATUS_CLAIM.getClaim(), status)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(getBadSecretKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenWithoutRoles(String subject, UserStatus status) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claim(STATUS_CLAIM.getClaim(), status)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateInvalidFormatToken() {
        return "this.is.not.a.jwt";
    }
}
