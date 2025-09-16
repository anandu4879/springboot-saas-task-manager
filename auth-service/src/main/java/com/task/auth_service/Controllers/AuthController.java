package com.task.auth_service.Controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.task.auth_service.Service.AuthService;
import com.task.auth_service.entity.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public User signup(@Valid @RequestBody SignupRequest request) {
        return authService.registerUser(request.getUsername(), request.getPassword(), request.getOrganization());
    }

    @PostMapping("/login")
    public String login(@Valid @RequestBody LoginRequest request) {
        System.out.println("Received LoginRequest: username=" + request.getUsername() + ", password=" + request.getPassword());
        return authService.login(request.getUsername(), request.getPassword());
    }

    static class SignupRequest {
        @NotBlank(message = "Username is required")
        @JsonProperty("username")
        private String username;

        @NotBlank(message = "Password is required")
        @JsonProperty("password")
        private String password;

        @NotBlank(message = "Organization name is required")
        @JsonProperty("organization")
        private String organization;

        // Getters
        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public String getOrganization() {
            return organization;
        }

        // Setters (optional, included for completeness)
        public void setUsername(String username) {
            this.username = username;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public void setOrganization(String organization) {
            this.organization = organization;
        }
    }

    static class LoginRequest {
        @NotBlank(message = "Username is required")
        private String username;

        @NotBlank(message = "Password is required")
        private String password;

        // Getters
        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        // Setters (optional, included for completeness)
        public void setUsername(String username) {
            this.username = username;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    @ControllerAdvice
    public class GlobalExceptionHandler {
        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
            Map<String, String> errors = new HashMap<>();
            for (FieldError error : ex.getBindingResult().getFieldErrors()) {
                errors.put(error.getField(), error.getDefaultMessage());
            }
            return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
        }
    }
}