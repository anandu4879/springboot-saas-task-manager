package com.task.auth_service.Service;

import com.task.auth_service.Repository.OrganizationRepository;
import com.task.auth_service.Repository.UserRepository;
import com.task.auth_service.config.JwtUtil;
import com.task.auth_service.entity.Organization;
import com.task.auth_service.entity.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepo;
    private final OrganizationRepository orgRepo;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthService(UserRepository userRepo, OrganizationRepository orgRepo, JwtUtil jwtUtil) {
        this.userRepo = userRepo;
        this.orgRepo = orgRepo;
        this.jwtUtil = jwtUtil;
    }

    public User registerUser(String username, String password, String orgName) {
        if (orgName == null || orgName.trim().isEmpty()) {
            throw new IllegalArgumentException("Organization name cannot be null or empty");
        }
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        Organization org = new Organization();
        org.setName(orgName);
        Organization savedOrg = orgRepo.save(org);

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("ADMIN");
        user.setOrgId(savedOrg.getId());
        return userRepo.save(user);
    }

    public String login(String username, String password) {
        System.out.println("Attempting login for username: " + username);
        User user = userRepo.findByUsername(username).orElseThrow(() -> {
            System.out.println("User not found: " + username);
            return new RuntimeException("Invalid credentials");
        });
        if (passwordEncoder.matches(password, user.getPassword())) {
            System.out.println("Password match for username: " + username);
            return jwtUtil.generateToken(user.getUsername(), user.getRole());
        }
        System.out.println("Password mismatch for username: " + username);
        throw new RuntimeException("Invalid credentials");
    }
}