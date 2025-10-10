package com.vendo.product_service.service;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.common.dto.JwtPayload;
import com.vendo.product_service.security.common.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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
public class JwtService {

    // TODO move to responsible class
    public static final String INVALID_TOKEN_FORMAT = "this.is.not.a.jwt";

    public static final String INVALID_STATUS = "INVALID_STATUS";

    @Autowired
    private JwtProperties jwtProperties;

    @Value("${security.jwt.bad-secret-key}")
    private String BAD_SECRET_KEY;

    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    public SecretKey getBadSecretKey() {
        return Keys.hmacShaKeyFor(BAD_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(JwtPayload jwtPayload) {
        return Jwts.builder()
                .subject(jwtPayload.getSubject())
                .claims(jwtPayload.getClaims())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtPayload.getExpiration()))
                .signWith(jwtPayload.getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // TODO investigate
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
}
