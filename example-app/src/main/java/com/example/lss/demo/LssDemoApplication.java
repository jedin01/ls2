package com.example.lss.demo;

import ao.sudojed.lss.annotation.EnableLazySecurity;
import ao.sudojed.lss.annotation.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

/**
 * LazySpringSecurity Demo Application
 * 
 * Demonstrates all LSS features:
 * - JWT Authentication (@Login, @Register, @RefreshToken)
 * - Authorization (@Secured, @Public, @Owner)
 * - Rate Limiting (@RateLimit)
 * - Caching (@Cached)
 * - Audit Logging (@Audit)
 * - LazyAuth utility methods
 * - LazyUser injection
 */
@SpringBootApplication
@EnableLazySecurity(
    jwt = @JwtConfig(
        secret = "${JWT_SECRET:my-super-secret-jwt-key-for-demo-purposes-only-change-in-production}",
        expiration = 900000,           // 15 minutes
        refreshExpiration = 86400000   // 24 hours
    )
)
@EnableCaching
public class LssDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(LssDemoApplication.class, args);
        
        System.out.println("\n" + "=".repeat(70));
        System.out.println("🚀 LazySpringSecurity Demo Application Started!");
        System.out.println("=".repeat(70));
        System.out.println("\n📚 Available Endpoints:");
        System.out.println("\n🔓 Public Endpoints (No Authentication Required):");
        System.out.println("  GET  http://localhost:8080/api/health");
        System.out.println("  GET  http://localhost:8080/api/public/products");
        System.out.println("  POST http://localhost:8080/api/auth/register");
        System.out.println("  POST http://localhost:8080/api/auth/login");
        System.out.println("  POST http://localhost:8080/api/auth/refresh");
        
        System.out.println("\n🔐 Authenticated Endpoints (Requires JWT Token):");
        System.out.println("  GET  http://localhost:8080/api/profile");
        System.out.println("  GET  http://localhost:8080/api/dashboard");
        System.out.println("  GET  http://localhost:8080/api/users/{userId}/orders");
        System.out.println("  POST http://localhost:8080/api/posts");
        System.out.println("  PUT  http://localhost:8080/api/posts/{id}");
        System.out.println("  GET  http://localhost:8080/api/cached-data");
        
        System.out.println("\n👑 Admin-Only Endpoints (Requires ADMIN role):");
        System.out.println("  GET  http://localhost:8080/api/admin/users");
        System.out.println("  GET  http://localhost:8080/api/admin/stats");
        System.out.println("  DELETE http://localhost:8080/api/admin/users/{id}");
        
        System.out.println("\n💡 Demo Users (auto-created on startup):");
        System.out.println("  Username: admin  | Password: admin123 | Roles: USER, ADMIN");
        System.out.println("  Username: john   | Password: john123  | Roles: USER");
        System.out.println("  Username: jane   | Password: jane123  | Roles: USER, MANAGER");
        
        System.out.println("\n📖 How to test:");
        System.out.println("  1. Register a new user or login with demo credentials");
        System.out.println("  2. Copy the access_token from login response");
        System.out.println("  3. Use it in Authorization header: Bearer <token>");
        System.out.println("  4. Try different endpoints to see LSS features in action");
        
        System.out.println("\n" + "=".repeat(70) + "\n");
    }
}
