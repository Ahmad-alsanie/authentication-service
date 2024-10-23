package com.quantum.authentication.filter;

import com.quantum.authentication.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class JwtRequestFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private UserDetailsService userDetailsService;

    @InjectMocks
    private JwtRequestFilter jwtRequestFilter;

    @Mock
    private FilterChain filterChain;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_ValidToken_ShouldSetAuthentication() throws ServletException, IOException {
        // Arrange
        String token = "validToken";
        String username = "johndoe";
        request.addHeader("Authorization", "Bearer " + token);

        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getUsername()).thenReturn(username);
        when(jwtUtil.extractUsername(token)).thenReturn(username);
        when(jwtUtil.validateToken(token, username)).thenReturn(true);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);

        // Act
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, times(1)).loadUserByUsername(username);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_InvalidToken_ShouldNotSetAuthentication() throws ServletException, IOException {
        // Arrange
        String token = "invalidToken";
        request.addHeader("Authorization", "Bearer " + token);

        when(jwtUtil.extractUsername(token)).thenReturn(null);
        when(jwtUtil.validateToken(token, null)).thenReturn(false);

        // Act
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_NoToken_ShouldNotSetAuthentication() throws ServletException, IOException {
        // Act
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_ExpiredToken_ShouldNotSetAuthentication() throws ServletException, IOException {
        // Arrange
        String token = "expiredToken";
        String username = "johndoe";
        request.addHeader("Authorization", "Bearer " + token);

        when(jwtUtil.extractUsername(token)).thenReturn(username);
        when(jwtUtil.validateToken(token, username)).thenReturn(false); // Simulate expired token

        // Act
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }


    @Test
    void doFilterInternal_MalformedToken_ShouldNotSetAuthentication() throws ServletException, IOException {
        // Arrange
        String token = "malformedToken";
        request.addHeader("Authorization", "Bearer " + token);

        when(jwtUtil.extractUsername(token)).thenThrow(new io.jsonwebtoken.MalformedJwtException("Malformed JWT"));

        // Act
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_TokenWithoutBearer_ShouldNotSetAuthentication() throws ServletException, IOException {
        // Arrange
        String token = "validToken";
        request.addHeader("Authorization", token); // Missing "Bearer "

        // Act
        jwtRequestFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }
}
