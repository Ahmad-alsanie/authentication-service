package com.quantum.authentication.service;

import com.quantum.authentication.model.UserEntity;
import com.quantum.authentication.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void saveUser_ShouldSaveUserSuccessfully() {
        // Arrange
        UserEntity user = new UserEntity();
        user.setUsername("johndoe");
        user.setPassword("password123");

        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword123");
        when(userRepository.save(user)).thenReturn(user);

        // Act
        UserEntity savedUser = userService.registerUser(user);

        // Assert
        assertNotNull(savedUser);
        assertEquals("johndoe", savedUser.getUsername());
        verify(userRepository, times(1)).save(user);
    }

    @Test
    void findUserById_UserExists_ShouldReturnUser() {
        long random = 1L;
        // Arrange
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername("johndoe");
        when(userRepository.findById(random)).thenReturn(Optional.of(user));

        // Act
        Optional<UserEntity> foundUser = userService.findUserById(
                random
        );

        // Assert
        assertTrue(foundUser.isPresent());
        assertEquals("johndoe", foundUser.get().getUsername());
        verify(userRepository, times(1)).findById(random);
    }

    @Test
    void findUserById_UserDoesNotExist_ShouldReturnEmpty() {
        long random = 1L;
        // Arrange
        when(userRepository.findById(random)).thenReturn(Optional.empty());

        // Act
        Optional<UserEntity> foundUser = userService.findUserById(random);

        // Assert
        assertFalse(foundUser.isPresent());
        verify(userRepository, times(1)).findById(random);
    }

    @Test
    void deleteUser_ShouldDeleteUserSuccessfully() {
        long random = 1L;

        userService.deleteUser(random);


        verify(userRepository, times(1)).deleteById(random);
    }

    @Test
    void deleteUser_NonExistentUser_ShouldDoNothing() {
        long random = 1L;
        // Arrange
        doNothing().when(userRepository).deleteById(random);

        // Act
        userService.deleteUser(random);

        // Assert
        verify(userRepository, times(1)).deleteById(random);
    }
}

