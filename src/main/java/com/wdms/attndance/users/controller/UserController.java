package com.wdms.attndance.users.controller;
import com.wdms.attndance.users.model.User;
import com.wdms.attndance.users.repositary.UserRepositary;
import com.wdms.attndance.users.service.UserService;
import com.wdms.attndance.users.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequestMapping("/api/users")   // base path
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepositary userRepositary;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")   // final path = /api/users/register
    public User createUser(@RequestBody User user) {
        return userService.createUser(user);
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User loginRequest) {
        User user = userRepositary.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            String token = jwtUtil.generateToken(user.getUsername());
            return Map.of("token", token);
        } else {
            throw new RuntimeException("Invalid credentials");
        }
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/all")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }
}
