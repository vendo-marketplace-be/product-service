package com.vendo.product_service.service;

import com.vendo.product_service.common.dto.JwtPayload;
import com.vendo.product_service.security.common.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${security.jwt.bad-secret-key}")
    private String BAD_SECRET_KEY;

    private final JwtProperties jwtProperties;

    public static final String ROLE_USER = "ROLE_USER";

    public static final String INVALID_STATUS = "INVALID_STATUS";

    public static final String INVALID_TOKEN_FORMAT = "INVALID_TOKEN_FORMAT";

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
}
