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

    public List<SimpleGrantedAuthority> parseRolesFromToken(Claims claims) {
        Object rolesClaim = claims.get(ROLES_CLAIM.getClaim());

        if (rolesClaim instanceof List<?> roles) {
            return roles.stream()
                    .map(Object::toString)
                    .map(SimpleGrantedAuthority::new)
                    .toList();
        }

        throw new IllegalArgumentException("Invalid roles");
    }

    public <T> Optional<T> extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return Optional.ofNullable(claimsResolver.apply(claims));
    }

    public Claims extractAllClaims(String token) {
        return parseSignedClaims(token)
                .getPayload();
    }

    public UserStatus parseUserStatus(Claims claims) throws IllegalArgumentException {
        Object status = claims.get(STATUS_CLAIM.getClaim());
        return UserStatus.valueOf(String.valueOf(status));
    }

    public Key getSignInKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    private Jws<Claims> parseSignedClaims(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith((SecretKey) getSignInKey())
                .build()
                .parseSignedClaims(token);
    }
}
