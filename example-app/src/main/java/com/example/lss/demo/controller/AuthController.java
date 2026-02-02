package com.example.lss.demo.controller;

import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.jwt.JwtProvider;
import ao.sudojed.lss.jwt.TokenPair;
import com.example.lss.demo.dto.LoginRequest;
import com.example.lss.demo.dto.RegisterRequest;
import com.example.lss.demo.model.User;
import com.example.lss.demo.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

/**
 * Authentication Controller demonstrating JWT features
 * 
 * Features demonstrated:
 * - User registration
 * - User login with JWT generation
 * - Token refresh
 * - JWT token handling
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtProvider jwtProvider;
    
    /**
     * FEATURE: User Registration
     * Demonstrates @Valid for input validation
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            User user = userService.createUser(
                request.getUsername(),
                request.getEmail(),
                request.getPassword()
            );
            
            return ResponseEntity.ok(Map.of(
                "message", "✅ User registered successfully",
                "feature", "@Valid annotation for input validation",
                "user", Map.of(
                    "id", user.getId(),
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "roles", user.getRoles()
                ),
                "tip", "Now login with: POST /api/auth/login"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", e.getMessage()
            ));
        }
    }
    
    /**
     * FEATURE: JWT Login
     * Demonstrates JWT token generation
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        User user = userService.findByUsername(request.getUsername())
                .orElse(null);
        
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid credentials"
            ));
        }
        
        // In real app, verify password hash
        // For demo, we'll just check some basic passwords
        String password = request.getPassword();
        if (!(password.equals("admin123") && request.getUsername().equals("admin") ||
              password.equals("john123") && request.getUsername().equals("john") ||
              password.equals("jane123") && request.getUsername().equals("jane") ||
              user.getPassword().equals(password))) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid credentials"
            ));
        }
        
        // Generate JWT tokens
        LazyUser lazyUser = LazyUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .roles(user.getRoles())
                .authenticated(true)
                .build();
        
        TokenPair tokens = jwtProvider.generateTokenPair(lazyUser);
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ Login successful",
            "feature", "JWT Token Generation",
            "access_token", tokens.accessToken(),
            "refresh_token", tokens.refreshToken(),
            "expires_in", 900, // 15 minutes
            "user", Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "roles", user.getRoles()
            ),
            "tip", "Use access_token in Authorization header: Bearer <token>"
        ));
    }
    
    /**
     * FEATURE: Token Refresh
     * Demonstrates JWT token refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");
        
        if (refreshToken == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Refresh token is required"
            ));
        }
        
        try {
            // Validate and extract user from refresh token
            LazyUser user = jwtProvider.extractUser(refreshToken);
            
            // Generate new access token
            String newAccessToken = jwtProvider.generateAccessToken(user);
            
            return ResponseEntity.ok(Map.of(
                "message", "✅ Token refreshed",
                "feature", "JWT Token Refresh",
                "access_token", newAccessToken,
                "expires_in", 900,
                "tip", "Refresh tokens allow getting new access tokens without re-login"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid or expired refresh token"
            ));
        }
    }
}
