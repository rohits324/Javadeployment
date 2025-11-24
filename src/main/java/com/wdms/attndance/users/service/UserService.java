package com.wdms.attndance.users.service;


import com.wdms.attndance.users.model.User;
import com.wdms.attndance.users.repositary.UserRepositary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    @Autowired
   private UserRepositary userRepositary;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserService(UserRepositary userRepositary) {
        this.userRepositary = userRepositary;
    }

    public User createUser(User user) {
       user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepositary.save(user);
    }

    public List<User> getAllUsers() {
        return userRepositary.findAll();
    }

}


