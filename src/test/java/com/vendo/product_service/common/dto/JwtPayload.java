package com.vendo.product_service.common.dto;

import lombok.Builder;
import lombok.Data;

import javax.crypto.SecretKey;
import java.util.Map;

@Data
@Builder
public class JwtPayload {

    private String subject;

    private Map<String, Object> claims;

    private SecretKey key;

    private int expiration;
}