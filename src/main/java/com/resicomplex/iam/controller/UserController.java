package com.resicomplex.iam.controller;

import com.resicomplex.iam.model.User;
import com.resicomplex.iam.model.UserRole;
import com.resicomplex.iam.model.UserStatus;
import com.resicomplex.iam.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP", "service", "iam-service");
    }

    @GetMapping("/api/v1/users")
    public List<User> listUsers() {
        return userService.findAll();
    }

    @GetMapping("/api/v1/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable String id) {
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/api/v1/users")
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest request) {
        try {
            User created = userService.create(
                    request.email(),
                    request.name(),
                    request.password(),
                    request.role()
            );
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/api/v1/users/{id}")
    public ResponseEntity<User> updateUser(@PathVariable String id, @RequestBody UpdateUserRequest request) {
        return userService.update(id, request.name(), request.role(), request.status())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/api/v1/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        return userService.deleteById(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @PostMapping("/api/v1/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return userService.login(request.email(), request.password())
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(Map.of(
                        "message", "Login exitoso",
                        "userId", user.getId(),
                        "email", user.getEmail(),
                        "role", user.getRole().name()
                )))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Credenciales inválidas o usuario inactivo")));
    }

    public record CreateUserRequest(String email, String name, String password, UserRole role) {}
    public record UpdateUserRequest(String name, UserRole role, UserStatus status) {}
    public record LoginRequest(String email, String password) {}
}
