package com.vendo.product_service.common.builder;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.type.TokenClaim;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.util.Date;
import java.util.List;

public class JwtTokenDataBuilder {

    public static JwtBuilder buildTokenWithRequiredFields(Key key) {
        return Jwts.builder()
                .claim(TokenClaim.STATUS_CLAIM.getClaim(), UserStatus.ACTIVE.name())
                .claim(TokenClaim.ROLES_CLAIM.getClaim(), List.of("ROLE_USER"))
                .subject("user@example.com")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(key);
    }
}
