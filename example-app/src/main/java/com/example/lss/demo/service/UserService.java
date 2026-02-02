package com.example.lss.demo.service;

import com.example.lss.demo.model.User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple user service for demo purposes
 */
@Service
public class UserService {
    
    private final Map<String, User> users = new ConcurrentHashMap<>();
    
    public UserService() {
        // Create demo users
        createDemoUsers();
    }
    
    private void createDemoUsers() {
        // Admin user
        User admin = new User();
        admin.setId("1");
        admin.setUsername("admin");
        admin.setEmail("admin@example.com");
        admin.setPassword("$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6"); // admin123
        admin.setRoles(Set.of("USER", "ADMIN"));
        users.put("admin", admin);
        
        // Regular user John
        User john = new User();
        john.setId("2");
        john.setUsername("john");
        john.setEmail("john@example.com");
        john.setPassword("$2a$10$8N6p5B5T5Y6vG5Y5Y5Y5YuY5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y"); // john123
        john.setRoles(Set.of("USER"));
        users.put("john", john);
        
        // Manager user Jane
        User jane = new User();
        jane.setId("3");
        jane.setUsername("jane");
        jane.setEmail("jane@example.com");
        jane.setPassword("$2a$10$9O7q6C6U6Z7wH6Z6Z6Z6ZvZ6Z6Z6Z6Z6Z6Z6Z6Z6Z6Z6Z6Z6Z6Z6Z"); // jane123
        jane.setRoles(Set.of("USER", "MANAGER"));
        users.put("jane", jane);
    }
    
    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }
    
    public Optional<User> findById(String id) {
        return users.values().stream()
                .filter(u -> u.getId().equals(id))
                .findFirst();
    }
    
    public User createUser(String username, String email, String password) {
        if (users.containsKey(username)) {
            throw new RuntimeException("Username already exists");
        }
        
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password); // Should be hashed in real app
        user.setRoles(Set.of("USER"));
        
        users.put(username, user);
        return user;
    }
    
    public List<User> findAll() {
        return new ArrayList<>(users.values());
    }
}
