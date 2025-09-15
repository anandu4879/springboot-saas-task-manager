package com.task.auth_service.Service;

import com.task.auth_service.Repository.OrganizationRepository;
import com.task.auth_service.Repository.UserRepository;
import com.task.auth_service.config.JwtUtil;
import com.task.auth_service.entity.Organization;
import com.task.auth_service.entity.User;
import com.task.auth_service.Repository.OrganizationRepository;
import com.task.auth_service.Repository.UserRepository;
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
        User user = userRepo.findByUsername(username).orElseThrow();
        if (passwordEncoder.matches(password, user.getPassword())) {
            return jwtUtil.generateToken(user.getUsername(), user.getRole());
        }
        throw new RuntimeException("Invalid credentials");
    }
}
