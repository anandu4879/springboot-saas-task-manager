package com.task.auth_service.Controllers;

import com.task.auth_service.Service.AuthService;
import com.task.auth_service.entity.User;
import com.task.auth_service.Service.AuthService;
import lombok.Data;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public User signup(@RequestBody SignupRequest request) {
        return authService.registerUser(request.username, request.password, request.organization);
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        return authService.login(request.username, request.password);
    }

    @Data
    static class SignupRequest {
        String username;
        String password;
        String organization;
    }

    @Data
    static class LoginRequest {
        String username;
        String password;
    }
}
