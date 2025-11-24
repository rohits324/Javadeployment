package com.wdms.attndance.users.repositary;

import com.wdms.attndance.users.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepositary extends JpaRepository<User ,Long> {
    Optional<User> findByUsername(String username);
}
