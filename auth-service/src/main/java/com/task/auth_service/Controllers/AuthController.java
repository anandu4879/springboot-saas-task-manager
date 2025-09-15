package com.task.auth_service.Controllers;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import com.task.auth_service.Service.AuthService;
import com.task.auth_service.entity.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

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
        return authService.registerUser(request.username, request.password, request.organization);
    }

    @PostMapping("/login")
    public String login(@Valid @RequestBody LoginRequest request) {
        System.out.println("Received LoginRequest: username=" + request.getUsername() + ", password=" + request.getPassword());
        return authService.login(request.username, request.password);
    }

    @Data
    static class SignupRequest {
        @NotBlank(message = "Username is required")
        @JsonProperty("username")
        String username;

        @NotBlank(message = "Password is required")
        @JsonProperty("password")
        String password;

        @NotBlank(message = "Organization name is required")
        @JsonProperty("organization")
        String organization;
    }
    @Data
    static class LoginRequest {
        @NotBlank(message = "Username is required")
        String username;
        @NotBlank(message = "Password is required")
        String password;
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