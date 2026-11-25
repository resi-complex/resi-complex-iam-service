package com.resicomplex.iam.service;

import com.resicomplex.iam.model.User;
import com.resicomplex.iam.model.UserRole;
import com.resicomplex.iam.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Test
    void createAndLoginUser() {
        when(userRepository.existsByEmail("admin@resicomplex.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        User created = userService.create("admin@resicomplex.com", "Admin", "Secret123!", UserRole.ADMINISTRATOR);
        assertEquals("admin@resicomplex.com", created.getEmail());
        assertEquals(UserRole.ADMINISTRATOR, created.getRole());

        when(userRepository.findByEmail("admin@resicomplex.com")).thenReturn(Optional.of(created));
        assertTrue(userService.login("admin@resicomplex.com", "Secret123!").isPresent());
        assertTrue(userService.login("admin@resicomplex.com", "WrongPass").isEmpty());
    }
}
