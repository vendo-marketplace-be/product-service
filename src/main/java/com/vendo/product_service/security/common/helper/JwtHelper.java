package com.vendo.product_service.security.common.helper;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.security.common.config.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;
import static com.vendo.security.common.type.TokenClaim.STATUS_CLAIM;

@Component
@RequiredArgsConstructor
public class JwtHelper {

    private final JwtProperties jwtProperties;

    public Optional<String> extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<SimpleGrantedAuthority> parseRolesFromToken(String token) {
        return extractClaim(token, claims -> claims.get(ROLES_CLAIM.getClaim()))
                .map(obj -> {
                    if (obj instanceof List<?> roles) {
                        return roles.stream()
                                .map(Object::toString)
                                .map(SimpleGrantedAuthority::new)
                                .toList();
                    }
                    return List.<SimpleGrantedAuthority>of();
                })
                .orElse(List.of());
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractClaim(token, Claims::getExpiration)
                    .map(expiration -> expiration.before(new Date()))
                    .orElse(true);
        } catch (ExpiredJwtException exception) {
            return true;
        } catch (JwtException exception) {
            return false;
        }
    }

    public <T> Optional<T> extractClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            Claims claims = extractAllClaims(token);
            return Optional.ofNullable(claimsResolver.apply(claims));
        } catch (JwtException e) {
            return Optional.empty();
        }
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public UserStatus parseUserStatus(String token) throws IllegalArgumentException {
        return extractClaim(token, claims -> claims.get(STATUS_CLAIM.getClaim()))
                .map(Object::toString)
                .map(statusStr -> {
                    try {
                        return UserStatus.valueOf(statusStr);
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("Invalid user status");
                    }
                })
                .orElseThrow(() -> new IllegalArgumentException("User status missing"));
    }

    public Key getSignInKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    private Jws<Claims> parseSignedClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) getSignInKey())
                .build()
                .parseSignedClaims(token);
    }

    public JwsHeader extractHeader(String token) {
        return parseSignedClaims(token)
                .getHeader();
    }
}
