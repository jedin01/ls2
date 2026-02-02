package com.example.lss.demo.model;

import java.util.HashSet;
import java.util.Set;

/**
 * User entity for demo purposes
 */
public class User {
    
    private String id;
    private String username;
    private String email;
    private String password;
    private Set<String> roles = new HashSet<>();
    private boolean active = true;
    
    public User() {}
    
    public User(String id, String username, String email, String password, Set<String> roles) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }
    
    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
    
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}
