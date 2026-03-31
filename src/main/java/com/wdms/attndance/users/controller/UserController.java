package com.wdms.attndance.users.controller;
import com.wdms.attndance.users.model.User;
import com.wdms.attndance.users.repositary.UserRepositary;
import com.wdms.attndance.users.service.UserService;
import com.wdms.attndance.users.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

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

//    @PostMapping("/register")   // final path = /api/users/register
//    public User createUser(@RequestBody User user) {
//        return userService.createUser(user);
//    }
        @PostMapping("/register")
        public ResponseEntity<?> createUser(@RequestBody User user) {
            //User existingUser = userRepositary.findByUsername(user.getUsername());
            Optional<User> existingUserOpt = userRepositary.findByUsername(user.getUsername());
            if (existingUserOpt.isPresent()) {
                return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .body("Username already exists");
            }

            User newUser = userService.createUser(user);
            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(newUser);
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
