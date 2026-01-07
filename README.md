# LazySpringSecurity (LSS)

> **A lightweight, annotation-driven security framework that abstracts Spring Security complexity into a readable, developer-friendly DSL.**

[![Java](https://img.shields.io/badge/Java-21+-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4+-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

- **Zero Configuration** - Works out of the box with sensible defaults
- **Annotation-Driven** - Simple, readable annotations for security
- **Fluent DSL** - Optional configuration with builder pattern
- **JWT Support** - Built-in JWT authentication with refresh tokens
- **Role & Permission Based** - Fine-grained access control
- **Spring Boot Native** - Seamless auto-configuration
- **Middleware Support** - Extensible request processing chain
- **Rate Limiting** - Built-in rate limiting support

---

## Installation

### Maven

```xml
<dependency>
    <groupId>ao.sudojed</groupId>
    <artifactId>lazy-spring-security</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### Gradle

```groovy
implementation 'ao.sudojed:lazy-spring-security:1.0.0-SNAPSHOT'
```

---

## Quick Start

### 1. Enable LazySpringSecurity

```java
@SpringBootApplication
@EnableLazySecurity
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### 2. Use Annotations

```java
@RestController
@RequestMapping("/api")
public class MyController {

    // Public endpoint - no authentication required
    @Public
    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    // Requires authentication (any logged-in user)
    @Secured
    @GetMapping("/profile")
    public User getProfile(Principal principal) {
        return userService.findById(principal.getId());
    }

    // Requires specific role
    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }

    // Multiple roles (any of them)
    @Secured({"ADMIN", "MODERATOR"})
    @PutMapping("/posts/{id}")
    public Post updatePost(@PathVariable Long id, @RequestBody Post post) {
        return postService.update(id, post);
    }

    // Resource owner only (or admin bypass)
    @Owner(value = "userId", allowRoles = {"ADMIN"})
    @GetMapping("/users/{userId}/settings")
    public Settings getSettings(@PathVariable String userId) {
        return settingsService.getByUserId(userId);
    }

    // Rate limiting
    @RateLimit(requests = 10, period = 1, unit = TimeUnit.MINUTES)
    @PostMapping("/send-email")
    public void sendEmail(@RequestBody EmailRequest request) {
        emailService.send(request);
    }
}
```

### 3. Configure JWT (application.yml)

```yaml
lazy-security:
  jwt:
    secret: ${JWT_SECRET:your-256-bit-secret-key-here}
    expiration: 24h
    refresh-enabled: true
```

---

## Annotations Reference

### `@Public`
Marks an endpoint as publicly accessible (no authentication required).

```java
@Public
@GetMapping("/docs")
public String getDocs() { ... }

// With reason for documentation
@Public(reason = "Health check for load balancer")
@GetMapping("/health")
public String health() { ... }
```

### `@Secured`
Unified security annotation for authentication and authorization.

```java
// Any authenticated user
@Secured
@GetMapping("/me")
public User getCurrentUser(Principal principal) { ... }

// Single role required
@Secured("ADMIN")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { ... }

// Multiple roles (OR logic - any role grants access)
@Secured({"ADMIN", "MODERATOR"})
@PutMapping("/posts/{id}")
public Post updatePost(@PathVariable Long id) { ... }

// Multiple roles (AND logic - all roles required)
@Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
@GetMapping("/exclusive-content")
public Content getExclusiveContent() { ... }

// With permissions
@Secured(permissions = "posts:write")
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) { ... }

// With SpEL condition
@Secured(condition = "#userId == principal.id")
@GetMapping("/users/{userId}/settings")
public Settings getSettings(@PathVariable String userId) { ... }

// Custom error message
@Secured(value = "ADMIN", message = "Only administrators can access this")
@GetMapping("/admin/config")
public Config getConfig() { ... }
```

### `@Secured` with Permissions
Fine-grained permission-based access control using the `permissions` attribute.

```java
@Secured(permissions = "posts:write")
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) { ... }

@Secured(permissions = {"billing:read", "billing:export"})
@GetMapping("/reports/billing")
public Report getBillingReport() { ... }

// Combine roles and permissions
@Secured(roles = "USER", permissions = "posts:write")
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) { ... }
```

### `@Owner`
Restricts access to the owner of a resource.

```java
// Match userId path variable with current user
@Owner("userId")
@GetMapping("/users/{userId}/settings")
public Settings getSettings(@PathVariable String userId) { ... }

// Allow admin to bypass ownership check
@Owner(value = "userId", allowRoles = {"ADMIN", "SUPPORT"})
@PutMapping("/users/{userId}")
public User updateUser(@PathVariable String userId) { ... }
```

### `@RateLimit`
Limits request rate to prevent abuse.

```java
// 10 requests per minute per IP
@RateLimit(requests = 10, period = 1, unit = TimeUnit.MINUTES)
@PostMapping("/login")
public AuthResponse login(@RequestBody LoginRequest request) { ... }

// 100 requests per hour per user
@RateLimit(requests = 100, unit = TimeUnit.HOURS, keyBy = KeyType.USER)
@GetMapping("/search")
public Results search(@RequestParam String q) { ... }
```

---

## Advanced Configuration

### Fluent DSL Configuration

```java
@Configuration
public class SecurityConfig {

    @Bean
    public LazySecurityConfigurer lazySecurity() {
        return LazySecurity.configure()
            // Public endpoints
            .publicPaths("/api/auth/**", "/health", "/docs/**")
            
            // Path-based rules
            .path("/api/admin/**").roles("ADMIN").and()
            .path("/api/moderator/**").roles("ADMIN", "MODERATOR").and()
            .path("/api/posts/**").methods("GET").permitAll().and()
            .path("/api/posts/**").methods("POST", "PUT", "DELETE").authenticated().and()
            
            // Default behavior
            .defaultAuthenticated()
            
            // JWT configuration
            .jwt(jwt -> jwt
                .secret("your-secret-key")
                .expirationHours(24)
                .refreshEnabled(true)
            )
            
            // Custom handlers
            .onAccessDenied((req, res, ex) -> {
                res.setStatus(403);
                res.getWriter().write("{\"error\": \"Access denied\"}");
            })
            
            // Options
            .cors(true)
            .csrf(false)
            .debug(true);
    }
}
```

### Custom Authentication Extractor

```java
@Component
public class ApiKeyAuthExtractor implements AuthenticationExtractor {

    @Override
    public Principal extract(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-Key");
        if (apiKey == null) return null;
        
        // Validate API key and return principal
        return apiKeyService.validate(apiKey)
            .map(key -> Principal.builder()
                .id(key.getClientId())
                .username(key.getClientName())
                .roles(key.getRoles())
                .build())
            .orElse(null);
    }

    @Override
    public int priority() {
        return 200; // Higher than JWT (100)
    }

    @Override
    public boolean supports(HttpServletRequest request) {
        return request.getHeader("X-API-Key") != null;
    }
}
```

### Custom Middleware

```java
@Component
public class AuditMiddleware implements Middleware {

    private final AuditService auditService;

    @Override
    public MiddlewareResult process(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    Principal principal) {
        auditService.log(
            request.getMethod(),
            request.getRequestURI(),
            principal != null ? principal.getId() : "anonymous"
        );
        
        return MiddlewareResult.proceed();
    }

    @Override
    public int getOrder() {
        return 10; // Early in chain
    }
}
```

### IP Blocking Middleware

```java
@Component
public class IpBlockMiddleware implements Middleware {

    private final Set<String> blockedIps;

    @Override
    public MiddlewareResult process(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Principal principal) {
        String clientIp = request.getRemoteAddr();
        
        if (blockedIps.contains(clientIp)) {
            return MiddlewareResult.deny("Your IP has been blocked", 403);
        }
        
        return MiddlewareResult.proceed();
    }
}
```

---

## JWT Authentication

### Generate Tokens

```java
@RestController
@RequestMapping("/api/auth")
@Public
public class AuthController {

    private final JwtProvider jwtProvider;
    private final UserService userService;

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        User user = userService.authenticate(request.username(), request.password());
        
        Principal principal = Principal.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles())
            .build();
        
        return jwtProvider.createTokenResponse(principal);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        String newToken = jwtProvider.refresh(request.refreshToken());
        
        if (newToken == null) {
            throw new AuthenticationException("Invalid refresh token");
        }
        
        return new TokenResponse(newToken, null, "Bearer", 86400);
    }
}
```

### Access Current User

```java
@GetMapping("/me")
@Secured
public UserResponse getCurrentUser(Principal principal) {
    // Principal is automatically injected
    return new UserResponse(
        principal.getId(),
        principal.getUsername(),
        principal.getRoles()
    );
}

// Or use SecurityContext anywhere
public void someMethod() {
    String userId = SecurityContext.userId().orElseThrow();
    boolean isAdmin = SecurityContext.hasRole("ADMIN");
}
```

---

## Configuration Properties

> ⚠️ **Important:** JWT expiration values should be in **milliseconds** when using programmatic configuration, or use the time format (e.g., `24h`, `7d`) in YAML.

```yaml
lazy-security:
  enabled: true              # Enable/disable LSS
  debug: false               # Enable debug logging
  default-mode: authenticated # authenticated, permit-all, deny-all
  
  public-paths:              # Paths that don't require auth
    - /api/public/**
    - /health
    - /actuator/**
  
  jwt:
    enabled: true
    secret: ${JWT_SECRET}    # Required for production
    expiration: 24h          # Access token expiration (supports: 1h, 24h, 7d, or ms)
    refresh-enabled: true
    refresh-expiration: 7d   # Refresh token expiration
    issuer: my-app
    header: Authorization
    prefix: "Bearer "
  
  cors:
    enabled: true
    allowed-origins:
      - http://localhost:3000
      - https://myapp.com
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
    allowed-headers:
      - "*"
    allow-credentials: true
    max-age: 3600
  
  csrf:
    enabled: false           # Usually disabled for REST APIs
```

---

## LazySpringSecurity vs Spring Security

| Feature | Spring Security | LazySpringSecurity |
|---------|-----------------|-------------------|
| Configuration | Complex Java config | Simple annotations + YAML |
| Learning Curve | Steep | Minimal |
| Boilerplate | High | Almost none |
| JWT Support | Manual setup | Built-in |
| Readability | Low | High |
| Flexibility | Very High | High |
| Method Security | `@PreAuthorize("hasRole('ADMIN')")` | `@Secured("ADMIN")` |
| Public Endpoints | Complex matcher config | `@Public` |

### Before (Spring Security)

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
    
    // Plus JwtAuthFilter, UserDetailsService, PasswordEncoder, etc...
}
```

### After (LazySpringSecurity)

```java
@SpringBootApplication
@EnableLazySecurity
public class MyApp { }

// That's it! Use @Public and @Secured on your endpoints
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Demo Application

The project includes a complete demo application in `ao.sudojed.lss.demo` that demonstrates all LSS features:

### Running the Demo

```bash
./mvnw spring-boot:run -Dspring-boot.run.main-class=ao.sudojed.lss.demo.DemoApplication
```

### Demo Users

| Username | Password | Roles |
|----------|----------|-------|
| admin    | admin123 | USER, ADMIN |
| john     | 123456   | USER |
| jane     | 123456   | USER, MANAGER |

### Demo Endpoints

**Public Endpoints:**
- `GET /auth/health` - Health check
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login and get JWT tokens
- `POST /auth/refresh` - Refresh access token

**Authenticated Endpoints:**
- `GET /api/profile` - Get user profile (uses LazyUser injection)
- `GET /api/me` - Get user info (uses Auth facade)
- `PUT /api/profile` - Update profile
- `GET /api/orders` - List user orders
- `POST /api/orders` - Create order

**Admin Endpoints:**
- `GET /api/admin/users` - List all users
- `GET /api/admin/dashboard` - Admin dashboard
- `GET /api/admin/reports` - Reports (ADMIN or MANAGER)

**Owner-Protected Endpoints:**
- `GET /api/users/{userId}/orders` - User orders (owner or admin)

### Test Coverage

The demo includes **73 tests** covering:
- AuthController (10 tests)
- ProfileController (9 tests)
- AdminController (20 tests)
- OrderController (15 tests)
- SimpleAuthController (5 tests)
- UserService (14 tests)

Run the demo tests:
```bash
./mvnw test -Dtest="ao.sudojed.lss.demo.**"
```

---

## Auth & Guard Facades

LSS provides two powerful facades for accessing security context without parameter injection.

### Auth Facade

Static access to the current authenticated user:

```java
import ao.sudojed.lss.facade.Auth;

@GetMapping("/me")
public Map<String, Object> getCurrentUser() {
    return Map.of(
        "id", Auth.id(),
        "username", Auth.username(),
        "email", Auth.claim("email"),
        "roles", Auth.user().getRoles(),
        "isAdmin", Auth.isAdmin(),
        "isGuest", Auth.guest()
    );
}

// Password hashing
String hash = Auth.hashPassword("plainPassword");
boolean valid = Auth.checkPassword("plainPassword", hash);
```

### Guard Facade

Imperative authorization checks:

```java
import ao.sudojed.lss.facade.Guard;

@GetMapping("/admin/dashboard")
public Map<String, Object> dashboard() {
    // Throws AccessDeniedException if not admin
    Guard.admin();
    
    return Map.of("stats", getStats());
}

@DeleteMapping("/users/{userId}")
public void deleteUser(@PathVariable String userId) {
    // Require ADMIN role
    Guard.role("ADMIN");
    
    // Or require any of these roles
    Guard.anyRole("ADMIN", "MODERATOR");
    
    // Check resource ownership (admin can bypass)
    Guard.owner(userId);
    
    userService.delete(userId);
}

// Fluent API
@GetMapping("/sensitive")
public Data sensitiveData() {
    Guard.check()
        .role("ADMIN")
        .permission("data:read")
        .authorize();
    
    return dataService.getSensitiveData();
}
```

---

## Contributing

Contributions are welcome! Please read our contributing guidelines first.

---

Made by Sudojed Team
