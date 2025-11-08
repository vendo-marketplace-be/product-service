package com.vendo.product_service.security.common.helper;

import com.vendo.product_service.security.common.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;

@Component
@RequiredArgsConstructor
public class JwtHelper {

    private final JwtProperties jwtProperties;

    public String extractSubject(String token) {
        return extractAllClaims(token).getSubject();
    }

    public List<SimpleGrantedAuthority> parseRolesFromToken(String token) {
        Object rolesObj = extractAllClaims(token).get(ROLES_CLAIM.getClaim());

        List<String> rolesList = rolesObj instanceof List<?> roles
                ? roles.stream().map(Object::toString).toList()
                : List.of();

        return rolesList.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    public Claims extractAllClaims(String token) {
        return parseSignedClaims(token).getPayload();
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
