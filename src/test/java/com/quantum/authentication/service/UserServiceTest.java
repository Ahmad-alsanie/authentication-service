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
        
        UserEntity user = new UserEntity();
        user.setUsername("johndoe");
        user.setPassword("password123");

        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword123");
        when(userRepository.save(user)).thenReturn(user);

        
        UserEntity savedUser = userService.registerUser(user);

        
        assertNotNull(savedUser);
        assertEquals("johndoe", savedUser.getUsername());
        verify(userRepository, times(1)).save(user);
    }

    @Test
    void findUserById_UserExists_ShouldReturnUser() {
        
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setUsername("johndoe");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        
        Optional<UserEntity> foundUser = userService.findUserById(1L);

        
        assertTrue(foundUser.isPresent());
        assertEquals("johndoe", foundUser.get().getUsername());
        verify(userRepository, times(1)).findById(1L);
    }

    @Test
    void findUserById_UserDoesNotExist_ShouldReturnEmpty() {
        
        
        when(userRepository.findById(1L)).thenReturn(Optional.empty());

        
        Optional<UserEntity> foundUser = userService.findUserById(1L);

        
        assertFalse(foundUser.isPresent());
        verify(userRepository, times(1)).findById(1L);
    }

    @Test
    void deleteUser_ShouldDeleteUserSuccessfully() {


        userService.deleteUser(1L);


        verify(userRepository, times(1)).deleteById(1L);
    }

    @Test
    void deleteUser_NonExistentUser_ShouldDoNothing() {

        
        doNothing().when(userRepository).deleteById(1L);

        
        userService.deleteUser(1L);

        
        verify(userRepository, times(1)).deleteById(1L);
    }
}

