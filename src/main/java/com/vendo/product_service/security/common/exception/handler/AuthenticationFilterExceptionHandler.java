package com.vendo.product_service.security.common.exception.handler;

import com.vendo.product_service.security.common.exception.InvalidTokenException;
import com.vendo.security.common.exception.AccessDeniedException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static jakarta.servlet.http.HttpServletResponse.*;

@Slf4j
@RestControllerAdvice
public class AuthenticationFilterExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException e) {
        return ResponseEntity.status(SC_FORBIDDEN).body(e.getMessage());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthenticationException(AuthenticationException e) {
        return ResponseEntity.status(SC_UNAUTHORIZED).body(e.getMessage());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Object> handleInvalidTokenException(InvalidTokenException e) {
        return ResponseEntity.status(SC_UNAUTHORIZED).body(e.getMessage());
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<Object> handleJwtException(JwtException e) {
        return ResponseEntity.status(SC_UNAUTHORIZED).body("Token has expired or invalid");
    }
}
