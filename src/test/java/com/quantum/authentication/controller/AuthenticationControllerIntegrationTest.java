package com.quantum.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quantum.authentication.TestSecurityConfiguration;
import com.quantum.authentication.dto.AuthenticationRequest;
import com.quantum.authentication.model.UserEntity;
import com.quantum.authentication.service.CustomUserDetailsService;
import com.quantum.authentication.service.UserService;
import com.quantum.authentication.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ContextConfiguration(classes = {TestSecurityConfiguration.class})
@AutoConfigureMockMvc
class AuthenticationControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private JwtUtil jwtUtil;

    @MockBean
    private CustomUserDetailsService userDetailsService;

    @MockBean
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    private UserEntity user;
    private AuthenticationRequest authRequest;

    @BeforeEach
    void setUp() {
        user = new UserEntity();
        user.setUsername("johndoe");
        user.setPassword("password123");

        authRequest = new AuthenticationRequest();
        authRequest.setUsername("johndoe");
        authRequest.setPassword("password123");
    }

    @Test
    void registerUser_ShouldReturnSuccessMessage() throws Exception {
        // Arrange
        when(userService.registerUser(any(UserEntity.class))).thenReturn(user);

        // Act & Assert
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(user)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully"));
    }

    @Test
    void registerUser_InvalidInput_ShouldReturnBadRequest() throws Exception {
        // Arrange
        UserEntity invalidUser = new UserEntity(); // Missing username and password

        // Act & Assert
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidUser)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createAuthenticationToken_ValidCredentials_ShouldReturnJwt() throws Exception {
        // Arrange
        String token = "mockedJwtToken";
        UserDetails userDetails = new User("johndoe", "password123", Collections.emptyList());

        when(authenticationManager.authenticate(any())).thenReturn(null); // Simulate successful authentication
        when(userDetailsService.loadUserByUsername(eq("johndoe"))).thenReturn(userDetails);
        when(jwtUtil.generateToken(eq("johndoe"))).thenReturn(token);

        // Act & Assert
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jwt").value(token));
    }

    @Test
    void createAuthenticationToken_InvalidCredentials_ShouldReturnUnauthorized() throws Exception {
        // Arrange
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Invalid username or password"));

        // Act & Assert
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Incorrect username or password"));
    }

    @Test
    void createAuthenticationToken_UserNotFound_ShouldReturnUnauthorized() throws Exception {
        // Arrange
        when(userDetailsService.loadUserByUsername(eq("johndoe"))).thenReturn(null);

        // Act & Assert
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized());
    }
}
