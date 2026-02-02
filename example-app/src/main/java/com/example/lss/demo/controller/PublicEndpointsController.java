package com.example.lss.demo.controller;

import ao.sudojed.lss.annotation.Public;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demonstrates @Public annotation
 * These endpoints are accessible without authentication
 */
@RestController
@RequestMapping("/api")
public class PublicEndpointsController {
    
    /**
     * FEATURE: @Public annotation
     * Makes endpoint publicly accessible without authentication
     */
    @Public
    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
            "status", "UP",
            "message", "✅ LazySpringSecurity Demo is running!",
            "feature", "@Public - No authentication required",
            "timestamp", System.currentTimeMillis()
        );
    }
    
    /**
     * FEATURE: @Public with documentation
     * Another public endpoint demonstrating LSS simplicity
     */
    @Public
    @GetMapping("/info")
    public Map<String, Object> info() {
        return Map.of(
            "application", "LSS Demo",
            "version", "1.0.0",
            "features", new String[]{
                "@Public", "@Secured", "@Owner", "@RateLimit", 
                "@Cached", "@Audit", "JWT Auth", "LazyAuth API"
            },
            "message", "This endpoint is @Public - accessible to everyone"
        );
    }
}
