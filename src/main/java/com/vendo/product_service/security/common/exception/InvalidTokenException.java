package com.vendo.product_service.security.common.exception;

import io.jsonwebtoken.JwtException;

// TODO move to common
public class InvalidTokenException extends JwtException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
