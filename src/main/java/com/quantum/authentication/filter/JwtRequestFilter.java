package com.quantum.authentication.filter;

import com.quantum.authentication.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRequestFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

            String username = null;
            String jwt = null;

            try {
                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    jwt = authorizationHeader.substring(7);
                    username = jwtUtil.extractUsername(jwt); // This may throw a MalformedJwtException or other JwtException
                }

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtUtil.validateToken(jwt, username)) {
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                        UsernamePasswordAuthenticationToken authenticationToken =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                }
            } catch (JwtException e) {
                LOGGER.error("JWT error: {}", e.getMessage());
            }

            chain.doFilter(request, response);
    }

}
