package com.example.lss.demo.controller;

import ao.sudojed.lss.annotation.Audit;
import ao.sudojed.lss.annotation.Cached;
import ao.sudojed.lss.annotation.Owner;
import ao.sudojed.lss.annotation.Public;
import ao.sudojed.lss.annotation.RateLimit;
import ao.sudojed.lss.annotation.Secured;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.util.LazyAuth;
import com.example.lss.demo.model.Order;
import com.example.lss.demo.model.Post;
import com.example.lss.demo.model.Product;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 🎯 COMPREHENSIVE LSS FEATURES DEMO
 * 
 * This controller demonstrates ALL LazySpringSecurity features:
 * 1. @Public - Public endpoints
 * 2. @Secured - Authentication required
 * 3. @Secured("ROLE") - Role-based authorization
 * 4. @Owner - Resource ownership verification
 * 5. @RateLimit - API rate limiting
 * 6. @Cached - Response caching
 * 7. @Audit - Audit logging
 * 8. LazyAuth - Utility methods
 * 9. LazyUser injection
 */
@RestController
@RequestMapping("/api")
public class AllFeaturesController {
    
    // In-memory storage for demo
    private final Map<Long, Post> posts = new ConcurrentHashMap<>();
    private final Map<String, List<Order>> ordersByUser = new ConcurrentHashMap<>();
    private final List<Product> products = new ArrayList<>();
    private final AtomicLong postIdCounter = new AtomicLong(1);
    private final AtomicLong orderIdCounter = new AtomicLong(1);
    
    public AllFeaturesController() {
        // Initialize demo data
        products.add(new Product(1L, "Laptop", "High-performance laptop", 1299.99, "Electronics"));
        products.add(new Product(2L, "Phone", "Latest smartphone", 899.99, "Electronics"));
        products.add(new Product(3L, "Book", "Programming guide", 49.99, "Books"));
    }
    
    // ==================== FEATURE 1: @Public ====================
    
    /**
     * FEATURE: @Public
     * Accessible without authentication
     */
    @Public
    @GetMapping("/public/products")
    public ResponseEntity<?> getPublicProducts() {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Public - No authentication needed",
            "products", products,
            "tip", "Anyone can access this endpoint"
        ));
    }
    
    // ==================== FEATURE 2: @Secured ====================
    
    /**
     * FEATURE: @Secured (any authenticated user)
     * Requires authentication but no specific role
     */
    @Secured
    @GetMapping("/dashboard")
    public ResponseEntity<?> getDashboard(LazyUser user) {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Secured - Authentication required",
            "feature", "Any authenticated user can access",
            "user", Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "roles", user.getRoles()
            ),
            "tip", "Use LazyUser for automatic user injection"
        ));
    }
    
    /**
     * FEATURE: @Secured + LazyAuth API
     * Demonstrates LazyAuth utility methods
     */
    @Secured
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        // FEATURE: LazyAuth utility methods
        String username = LazyAuth.username();
        String userId = LazyAuth.userId();
        Set<String> roles = LazyAuth.user().getRoles();
        boolean isAdmin = LazyAuth.hasRole("ADMIN");
        boolean hasAnyRole = LazyAuth.hasAnyRole("ADMIN", "MANAGER");
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Secured + LazyAuth API",
            "feature", "LazyAuth provides utility methods",
            "profile", Map.of(
                "username", username,
                "userId", userId,
                "roles", roles,
                "isAdmin", isAdmin,
                "hasAdminOrManager", hasAnyRole
            ),
            "tip", "Use LazyAuth.username(), LazyAuth.hasRole(), etc."
        ));
    }
    
    // ==================== FEATURE 3: @Secured with Roles ====================
    
    /**
     * FEATURE: @Secured("ADMIN")
     * Only users with ADMIN role can access
     */
    @Secured("ADMIN")
    @GetMapping("/admin/stats")
    public ResponseEntity<?> getAdminStats() {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Secured(\"ADMIN\") - Role-based authorization",
            "feature", "Only ADMIN role can access",
            "stats", Map.of(
                "totalUsers", 3,
                "totalPosts", posts.size(),
                "totalOrders", ordersByUser.values().stream().mapToInt(List::size).sum()
            ),
            "tip", "Try accessing as non-admin user - it will be denied"
        ));
    }
    
    /**
     * FEATURE: @Secured with multiple roles
     * Users with ADMIN OR MANAGER can access
     */
    @Secured({"ADMIN", "MANAGER"})
    @GetMapping("/reports")
    public ResponseEntity<?> getReports() {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Secured({\"ADMIN\", \"MANAGER\"})",
            "feature", "Multiple roles (any of them)",
            "report", Map.of(
                "generatedBy", LazyAuth.username(),
                "userRole", LazyAuth.user().getRoles(),
                "data", "Sensitive report data"
            ),
            "tip", "User needs ADMIN OR MANAGER role"
        ));
    }
    
    // ==================== FEATURE 4: @Owner ====================
    
    /**
     * FEATURE: @Owner with path variable
     * User can only access their own orders
     */
    @Owner(field = "userId")
    @GetMapping("/users/{userId}/orders")
    public ResponseEntity<?> getUserOrders(@PathVariable String userId) {
        List<Order> orders = ordersByUser.getOrDefault(userId, new ArrayList<>());
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Owner(field = \"userId\")",
            "feature", "Ownership verification on path variable",
            "userId", userId,
            "orders", orders,
            "tip", "User can only see their own orders. Try accessing another user's orders!"
        ));
    }
    
    /**
     * FEATURE: @Owner with adminBypass
     * User can access their data, Admin can access anyone's data
     */
    @Owner(field = "userId", adminBypass = true)
    @GetMapping("/users/{userId}/sensitive-data")
    public ResponseEntity<?> getSensitiveData(@PathVariable String userId) {
        boolean isAdmin = LazyAuth.hasRole("ADMIN");
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Owner(field = \"userId\", adminBypass = true)",
            "feature", "Ownership with admin bypass",
            "userId", userId,
            "accessedBy", LazyAuth.username(),
            "isAdminAccess", isAdmin,
            "data", "Sensitive user data",
            "tip", "Regular users see their own data, admins can see anyone's"
        ));
    }
    
    /**
     * FEATURE: @Owner with entity field
     * User can only edit their own posts
     */
    @Owner(entityField = "createdBy", entity = Post.class)
    @PutMapping("/posts/{id}")
    public ResponseEntity<?> updatePost(@PathVariable Long id, @RequestBody Map<String, String> updates) {
        Post post = posts.get(id);
        if (post == null) {
            return ResponseEntity.notFound().build();
        }
        
        // Update post
        if (updates.containsKey("title")) post.setTitle(updates.get("title"));
        if (updates.containsKey("content")) post.setContent(updates.get("content"));
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Owner(entityField = \"createdBy\", entity = Post.class)",
            "feature", "Ownership verification on entity field",
            "post", post,
            "tip", "User can only edit their own posts. LSS automatically checks post.createdBy"
        ));
    }
    
    // ==================== FEATURE 5: @RateLimit ====================
    
    /**
     * FEATURE: @RateLimit
     * Limits requests per time window
     */
    @RateLimit(requests = 5, windowInSeconds = 60)
    @Public
    @GetMapping("/limited")
    public ResponseEntity<?> rateLimitedEndpoint() {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @RateLimit(requests = 5, windowInSeconds = 60)",
            "feature", "Rate limiting protection",
            "limit", "5 requests per 60 seconds",
            "timestamp", System.currentTimeMillis(),
            "tip", "Try calling this endpoint more than 5 times in a minute!"
        ));
    }
    
    /**
     * FEATURE: @RateLimit with perUser
     * Rate limit per authenticated user
     */
    @RateLimit(requests = 10, windowInSeconds = 60, perUser = true)
    @Secured
    @PostMapping("/upload")
    public ResponseEntity<?> upload(@RequestBody Map<String, Object> data) {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @RateLimit(requests = 10, windowInSeconds = 60, perUser = true)",
            "feature", "Per-user rate limiting",
            "user", LazyAuth.username(),
            "limit", "10 uploads per minute per user",
            "tip", "Each authenticated user has their own rate limit"
        ));
    }
    
    // ==================== FEATURE 6: @Cached ====================
    
    /**
     * FEATURE: @Cached
     * Caches response for specified TTL
     */
    @Cached(ttl = 300)
    @Public
    @GetMapping("/cached-data")
    public ResponseEntity<?> getCachedData() {
        // Simulate expensive operation
        long computedValue = System.currentTimeMillis();
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Cached(ttl = 300)",
            "feature", "Response caching for 5 minutes",
            "computedValue", computedValue,
            "tip", "Call multiple times - you'll get the same computedValue for 5 minutes"
        ));
    }
    
    /**
     * FEATURE: @Cached with perUser
     * Caches response per authenticated user
     */
    @Cached(ttl = 180, perUser = true)
    @Secured
    @GetMapping("/user-cached-data")
    public ResponseEntity<?> getUserCachedData() {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Cached(ttl = 180, perUser = true)",
            "feature", "Per-user caching",
            "user", LazyAuth.username(),
            "generatedAt", System.currentTimeMillis(),
            "tip", "Each user gets their own cached version"
        ));
    }
    
    // ==================== FEATURE 7: @Audit ====================
    
    /**
     * FEATURE: @Audit
     * Logs all accesses to this endpoint
     */
    @Audit(action = "VIEW_SENSITIVE_DATA")
    @Secured("ADMIN")
    @GetMapping("/admin/users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Audit(action = \"VIEW_SENSITIVE_DATA\")",
            "feature", "Audit logging",
            "users", Arrays.asList("admin", "john", "jane"),
            "auditedBy", LazyAuth.username(),
            "tip", "All accesses to this endpoint are logged"
        ));
    }
    
    /**
     * FEATURE: @Audit with high level
     * Critical operations logging
     */
    @Audit(action = "DELETE_USER", level = ao.sudojed.lss.annotation.AuditLevel.HIGH)
    @Secured("ADMIN")
    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id) {
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Audit(action = \"DELETE_USER\", level = HIGH)",
            "feature", "High-level audit logging",
            "deletedUserId", id,
            "deletedBy", LazyAuth.username(),
            "tip", "Critical operations are logged with HIGH level"
        ));
    }
    
    // ==================== COMBINED FEATURES ====================
    
    /**
     * FEATURE: Multiple annotations combined
     * Demonstrates using multiple LSS features together
     */
    @Secured
    @RateLimit(requests = 3, windowInSeconds = 60, perUser = true)
    @Audit(action = "CREATE_POST")
    @PostMapping("/posts")
    public ResponseEntity<?> createPost(@Valid @RequestBody Map<String, String> postData) {
        Long id = postIdCounter.getAndIncrement();
        Post post = new Post(
            id,
            postData.get("title"),
            postData.get("content"),
            LazyAuth.userId()
        );
        posts.put(id, post);
        
        return ResponseEntity.ok(Map.of(
            "message", "✅ @Secured + @RateLimit + @Audit",
            "feature", "Multiple LSS annotations combined",
            "post", post,
            "features", Arrays.asList(
                "@Secured - Authentication required",
                "@RateLimit - Max 3 posts per minute",
                "@Audit - All post creations logged"
            ),
            "tip", "LSS annotations work seamlessly together!"
        ));
    }
    
    /**
     * FEATURE: All features demo
     * The ultimate LSS showcase endpoint
     */
    @Secured("ADMIN")
    @RateLimit(requests = 10, windowInSeconds = 60, perUser = true)
    @Cached(ttl = 60)
    @Audit(action = "DEMO_ALL_FEATURES", level = ao.sudojed.lss.annotation.AuditLevel.MEDIUM)
    @GetMapping("/demo/all-features")
    public ResponseEntity<?> demoAllFeatures() {
        return ResponseEntity.ok(Map.of(
            "message", "🎉 ALL LSS FEATURES IN ONE ENDPOINT!",
            "features", Map.of(
                "@Secured(\"ADMIN\")", "Only admins can access",
                "@RateLimit", "Max 10 requests per minute",
                "@Cached(ttl = 60)", "Response cached for 1 minute",
                "@Audit", "Every access is logged"
            ),
            "user", Map.of(
                "id", LazyAuth.userId(),
                "username", LazyAuth.username(),
                "roles", LazyAuth.user().getRoles()
            ),
            "timestamp", System.currentTimeMillis(),
            "tip", "This endpoint demonstrates ALL LSS features working together!"
        ));
    }
}
