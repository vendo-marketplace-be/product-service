package com.vendo.product_service.security.filter;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.type.TokenClaim;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.util.Date;
import java.util.List;

public class JwtTestHelper {

    public static String createToken(Key key, String subject, UserStatus status, List<String> roles) {
        return Jwts.builder()
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), status.name())
                .claim(TokenClaim.ROLES_CLAIM.getClaim(), roles)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();
    }

    public static String createExpiredToken(Key key, String subject, UserStatus status, List<String> roles) {
        return Jwts.builder()
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), status.name())
                .claim(TokenClaim.ROLES_CLAIM.getClaim(), roles)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() - 3600000))
                .signWith(key)
                .compact();
    }
}
