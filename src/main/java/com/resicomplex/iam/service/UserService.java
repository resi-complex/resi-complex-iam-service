package com.resicomplex.iam.service;

import com.resicomplex.iam.model.User;
import com.resicomplex.iam.model.UserRole;
import com.resicomplex.iam.model.UserStatus;
import com.resicomplex.iam.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }

    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }

    public User create(String email, String name, String rawPassword, UserRole role) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("El correo ya está registrado: " + email);
        }
        User user = new User();
        user.setEmail(email.trim().toLowerCase());
        user.setName(name);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setRole(role != null ? role : UserRole.PERSON);
        user.setStatus(UserStatus.ACTIVE);
        return userRepository.save(user);
    }

    public Optional<User> update(String id, String name, UserRole role, UserStatus status) {
        return userRepository.findById(id).map(existing -> {
            if (name != null) existing.setName(name);
            if (role != null) existing.setRole(role);
            if (status != null) existing.setStatus(status);
            return userRepository.save(existing);
        });
    }

    public boolean deleteById(String id) {
        if (!userRepository.existsById(id)) {
            return false;
        }
        userRepository.deleteById(id);
        return true;
    }

    public Optional<User> login(String email, String rawPassword) {
        return userRepository.findByEmail(email.trim().toLowerCase())
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .filter(u -> passwordEncoder.matches(rawPassword, u.getPasswordHash()));
    }
}
