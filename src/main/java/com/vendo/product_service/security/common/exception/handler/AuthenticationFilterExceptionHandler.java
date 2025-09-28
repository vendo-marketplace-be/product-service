package com.vendo.product_service.security.common.exception.handler;

import com.vendo.security.common.exception.AccessDeniedException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class AuthenticationFilterExceptionHandler {

    public void handle(Exception e, HttpServletResponse response) {

        if (e instanceof AccessDeniedException) {
            log.warn("AccessDeniedException: {}", e.getMessage());
            writeExceptionResponse(e.getMessage(), HttpStatus.SC_FORBIDDEN, response);
            return;
        }

        if (e instanceof AuthenticationException) {
            log.warn("AuthenticationException: {}", e.getMessage());
            writeExceptionResponse(e.getMessage(), HttpStatus.SC_UNAUTHORIZED, response);
            return;
        }

        if (e instanceof JwtException) {
            log.warn("JwtException: {}", e.getMessage());
            writeExceptionResponse("Token has expired or invalid", HttpStatus.SC_UNAUTHORIZED, response);
        }
    }

    private void writeExceptionResponse(Object responseTarget, int statusCode, HttpServletResponse response) {
        try {
            if (responseTarget == null) {
                throw new IllegalArgumentException("Response target cannot be null");
            }

            response.setStatus(statusCode);
            response.getWriter().write(String.valueOf(responseTarget));
        } catch (IOException e) {
            log.error("IOException: ", e);
        }
    }
}
