package ao.sudojed.lss.demo.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Modelo de usuário para demonstração.
 * Em uma aplicação real, seria uma entidade JPA.
 */
public class User {
    
    private String id;
    private String username;
    private String email;
    private String displayName;
    private String passwordHash;
    private Set<String> roles;
    private LocalDateTime createdAt;

    public User() {
        this.roles = new HashSet<>();
        this.createdAt = LocalDateTime.now();
    }

    public User(String id, String username, String email, String passwordHash) {
        this();
        this.id = id;
        this.username = username;
        this.email = email;
        this.displayName = username;
        this.passwordHash = passwordHash;
    }

    // Getters e Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public void addRole(String role) {
        this.roles.add(role);
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
