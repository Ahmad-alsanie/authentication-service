package com.quantum.authentication.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private SecretKey secretKey;
    private static final long JWT_EXPIRATION = 3600000; // 1 hour in milliseconds
    private static final String USERNAME = "johndoe";

    @BeforeEach
    void setUp() {
        // Generate a SecretKey for testing
        secretKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        String base64Secret = java.util.Base64.getEncoder().encodeToString(secretKey.getEncoded());

        // Initialize JwtUtil with the generated base64 secret key and expiration time
        jwtUtil = new JwtUtil(base64Secret, JWT_EXPIRATION);
    }

    @Test
    void generateToken_ShouldGenerateValidToken() {
        
        String token = jwtUtil.generateToken(USERNAME);

        
        assertNotNull(token);
        assertTrue(token.startsWith("eyJ")); // JWT typically starts with a base64-encoded header
    }

    @Test
    void extractUsername_ShouldExtractCorrectUsername() {
        
        String token = jwtUtil.generateToken(USERNAME);

        
        String extractedUsername = jwtUtil.extractUsername(token);

        
        assertEquals(USERNAME, extractedUsername);
    }

    @Test
    void isTokenExpired_ShouldReturnFalseForValidToken() {
        
        String token = jwtUtil.generateToken(USERNAME);

        
        boolean isExpired = jwtUtil.isTokenExpired(token);

        
        assertFalse(isExpired);
    }

    @Test
    void isTokenExpired_ShouldReturnTrueForExpiredToken() {

        String expiredToken = Jwts.builder()
                .setSubject(USERNAME)
                .setIssuedAt(new Date(System.currentTimeMillis() - 10000)) // Issued 10 seconds ago
                .setExpiration(new Date(System.currentTimeMillis() - 5000)) // Expired 5 seconds ago
                .signWith(secretKey)
                .compact();
        
        assertThrows(ExpiredJwtException.class, ()->jwtUtil.isTokenExpired(expiredToken));
    }

    @Test
    void validateToken_ShouldReturnTrueForValidToken() {
        
        String token = jwtUtil.generateToken(USERNAME);

        
        boolean isValid = jwtUtil.validateToken(token, USERNAME);

        
        assertTrue(isValid);
    }

    @Test
    void validateToken_ShouldReturnFalseForInvalidUsername() {
        
        String token = jwtUtil.generateToken(USERNAME);

        
        boolean isValid = jwtUtil.validateToken(token, "janedoe");

        
        assertFalse(isValid);
    }

    @Test
    void validateToken_ShouldReturnFalseForExpiredToken() {
        String expiredToken = Jwts.builder()
                .setSubject(USERNAME)
                .setIssuedAt(new Date(System.currentTimeMillis() - 10000)) // Issued 10 seconds ago
                .setExpiration(new Date(System.currentTimeMillis() - 5000)) // Expired 5 seconds ago
                .signWith(secretKey)
                .compact();

        assertThrows(ExpiredJwtException.class, ()->jwtUtil.validateToken(expiredToken, USERNAME));
    }
}

