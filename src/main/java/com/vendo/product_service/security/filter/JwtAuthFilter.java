package com.vendo.product_service.security.filter;

import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.product_service.security.common.exception.InvalidTokenException;
import com.vendo.product_service.security.common.helper.JwtHelper;
import com.vendo.security.common.exception.AccessDeniedException;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.List;

import static com.vendo.security.common.constants.AuthConstants.AUTHORIZATION_HEADER;
import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtHelper jwtHelper;

    private final ProductAntPathResolver productAntPathResolver;

    @Qualifier("handlerExceptionResolver")
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwtToken = getTokenFromRequest(request);
            Claims claims = jwtHelper.extractAllClaims(jwtToken);

            String subject = validateUserAccessibility(jwtToken, claims);
            addAuthenticationToContext(subject, jwtHelper.parseRolesFromToken(claims));
        } catch (Exception e) {
            handlerExceptionResolver.resolveException(request, response, null, e);
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return productAntPathResolver.isPermittedPath(requestURI);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader(AUTHORIZATION_HEADER);

        if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
            return authorization.substring(BEARER_PREFIX.length());
        }

        throw new InvalidTokenException("Missing or invalid Authorization header");
    }

    private String validateUserAccessibility(String jwtToken, Claims claims) {
        UserStatus status = jwtHelper.parseUserStatus(claims);

        if (status == UserStatus.BLOCKED) {
            throw new AccessDeniedException("User is blocked");
        }

        return jwtHelper.extractSubject(jwtToken)
                .orElseThrow(() -> new InvalidTokenException("Token subject missing"));
    }

    private void addAuthenticationToContext(String subject, List<SimpleGrantedAuthority> roles) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                subject,
                null,
                roles
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}