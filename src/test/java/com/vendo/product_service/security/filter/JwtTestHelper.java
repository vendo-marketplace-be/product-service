package com.vendo.product_service.security.filter;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.type.TokenClaim;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import java.util.Date;

public class JwtTestHelper {

    public static String createToken(Key key, String subject, UserStatus status) {
        return Jwts.builder()
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), status.name())
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public static String createExpiredToken(Key key, String subject, UserStatus status) {
        return Jwts.builder()
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), status.name())
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis() - 7200000))
                .setExpiration(new Date(System.currentTimeMillis() - 3600000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
