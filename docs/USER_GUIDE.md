# LazySpringSecurity - User Guide

> **Complete guide to using LazySpringSecurity (LSS) - A lightweight, annotation-driven security framework for Spring Boot.**

---

## Table of Contents

1. [Getting Started](#getting-started)
   - [Installation](#installation)
   - [Quick Start](#quick-start)
   - [Minimal Configuration](#minimal-configuration)
2. [Configuration](#configuration)
   - [@EnableLazySecurity Options](#enablelazysecurity-options)
   - [@JwtConfig Options](#jwtconfig-options)
   - [application.yml Properties](#applicationyml-properties)
   - [Environment Variables](#environment-variables)
3. [Annotations Reference](#annotations-reference)
   - [@Secured](#secured)
   - [@Public](#public)
   - [@Owner](#owner)
   - [@RateLimit](#ratelimit)
   - [@Audit](#audit)
   - [@Cached](#cached)
   - [@Login, @Register, @RefreshToken](#login-register-refreshtoken)
   - [@Authenticatable](#authenticatable)
4. [Facades Reference](#facades-reference)
   - [Auth Facade](#auth-facade)
   - [Guard Facade](#guard-facade)
5. [Advanced Topics](#advanced-topics)
   - [Custom JWT Provider](#custom-jwt-provider)
   - [Token Revocation](#token-revocation)
   - [SpEL Conditions](#spel-conditions)
   - [Annotation Inheritance](#annotation-inheritance)
   - [Error Handling](#error-handling)
6. [Examples](#examples)
   - [REST API with JWT](#rest-api-with-jwt)
   - [Role-Based Access Control](#role-based-access-control)
   - [Resource Ownership](#resource-ownership)
   - [Rate Limiting](#rate-limiting)
7. [Migration Guide](#migration-guide)
   - [From Spring Security](#from-spring-security)
   - [From Deprecated Annotations](#from-deprecated-annotations)
8. [Troubleshooting](#troubleshooting)
   - [Common Issues](#common-issues)
   - [Debug Mode](#debug-mode)
   - [Logging Configuration](#logging-configuration)

---

## Getting Started

### Installation

#### Maven

```xml
<dependency>
    <groupId>ao.sudojed</groupId>
    <artifactId>lazy-spring-security</artifactId>
    <version>1.1.0</version>
</dependency>
```

#### Gradle

```groovy
implementation 'ao.sudojed:lazy-spring-security:1.1.0'
```

### Quick Start

1. **Enable LazySpringSecurity** in your main application class:

```java
@EnableLazySecurity(
    jwt = @JwtConfig(secret = "${JWT_SECRET}")
)
@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

2. **Create your first protected endpoint**:

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @Public
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }

    @Secured
    @GetMapping("/profile")
    public Map<String, Object> getProfile(LazyUser user) {
        return Map.of(
            "id", user.getId(),
            "username", user.getUsername(),
            "roles", user.getRoles()
        );
    }

    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        // Only admins can delete users
    }
}
```

3. **Set your JWT secret** in environment or application.yml:

```yaml
# application.yml
JWT_SECRET: your-256-bit-secret-key-at-least-32-characters
```

### Minimal Configuration

The absolute minimum configuration is:

```java
@EnableLazySecurity
@SpringBootApplication
public class MyApplication { }
```

With `application.yml`:

```yaml
lazy-security:
  jwt:
    secret: ${JWT_SECRET:default-dev-secret-change-in-production}
```

---

## Configuration

### @EnableLazySecurity Options

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `jwt` | @JwtConfig | - | JWT configuration |
| `publicPaths` | String[] | {} | Paths that don't require authentication |
| `defaultRole` | String | "USER" | Default role for authenticated users |
| `csrfEnabled` | boolean | false | Enable CSRF protection |
| `corsEnabled` | boolean | true | Enable CORS |
| `corsOrigins` | String[] | {"*"} | Allowed CORS origins |
| `corsMethods` | String[] | GET, POST, PUT, DELETE, PATCH, OPTIONS | Allowed HTTP methods |
| `corsHeaders` | String[] | {"*"} | Allowed headers |
| `securePaths` | String[] | {} | Paths that require HTTPS |
| `debug` | boolean | false | Enable debug logging |

**Example:**

```java
@EnableLazySecurity(
    jwt = @JwtConfig(
        secret = "${JWT_SECRET}",
        expiration = 3600000,  // 1 hour
        refreshExpiration = 604800000  // 7 days
    ),
    publicPaths = {"/api/auth/**", "/health", "/swagger-ui/**"},
    defaultRole = "USER",
    csrfEnabled = false,
    corsEnabled = true,
    corsOrigins = {"http://localhost:3000", "https://myapp.com"},
    debug = true
)
@SpringBootApplication
public class MyApplication { }
```

### @JwtConfig Options

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `secret` | String | "" | Secret key for signing (min 32 chars for HS256) |
| `expiration` | long | 3600000 | Access token expiration (ms) - 1 hour |
| `refreshExpiration` | long | 604800000 | Refresh token expiration (ms) - 7 days |
| `header` | String | "Authorization" | HTTP header name |
| `prefix` | String | "Bearer " | Token prefix in header |
| `issuer` | String | "lazy-spring-security" | JWT issuer claim |
| `audience` | String | "" | JWT audience claim |
| `algorithm` | String | "HS256" | Signing algorithm |

### application.yml Properties

```yaml
lazy-security:
  enabled: true
  debug: false
  default-role: USER
  
  public-paths:
    - /api/public/**
    - /health
    - /actuator/**
  
  jwt:
    enabled: true
    secret: ${JWT_SECRET}
    expiration: 3600000      # 1 hour in milliseconds
    refresh-expiration: 604800000  # 7 days
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
    enabled: false
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | JWT signing secret (required in production) |
| `LSS_DEBUG` | Enable debug mode (true/false) |
| `LSS_PUBLIC_PATHS` | Comma-separated public paths |

---

## Annotations Reference

### @Secured

The unified security annotation for authentication and authorization.

**Usage Patterns:**

```java
// Any authenticated user
@Secured
@GetMapping("/profile")
public User getProfile() { }

// Single role required
@Secured("ADMIN")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { }

// Multiple roles (any of them - OR logic)
@Secured({"ADMIN", "MANAGER"})
@GetMapping("/reports")
public List<Report> getReports() { }

// All roles required (AND logic)
@Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
@GetMapping("/premium-content")
public Content getPremiumContent() { }

// With permissions
@Secured(permissions = "users:read")
@GetMapping("/users")
public List<User> listUsers() { }

// Combine roles and permissions
@Secured(roles = "USER", permissions = "posts:write")
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) { }

// With SpEL condition
@Secured(condition = "#userId == #principal.id")
@GetMapping("/users/{userId}/settings")
public Settings getSettings(@PathVariable String userId) { }

// Custom error message
@Secured(value = "ADMIN", message = "Only administrators can access this")
@GetMapping("/admin/config")
public Config getConfig() { }

// Class-level (applies to all methods)
@Secured("ADMIN")
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    // All endpoints require ADMIN role
}
```

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `value` | String[] | {} | Roles (shorthand) |
| `roles` | String[] | {} | Roles (alias for value) |
| `permissions` | String[] | {} | Required permissions |
| `all` | boolean | false | Require ALL roles (AND vs OR) |
| `message` | String | "Access denied" | Error message |
| `condition` | String | "" | SpEL expression |

### @Public

Marks an endpoint as publicly accessible.

```java
@Public
@GetMapping("/health")
public String health() {
    return "OK";
}

@Public
@PostMapping("/auth/login")
public TokenResponse login(@RequestBody LoginRequest request) { }
```

### @Owner

Validates resource ownership.

```java
// Basic - check path variable
@Secured
@Owner(field = "userId")
@GetMapping("/users/{userId}/orders")
public List<Order> getOrders(@PathVariable String userId) { }

// With admin bypass
@Secured
@Owner(field = "userId", adminBypass = true)
@PutMapping("/users/{userId}")
public User updateUser(@PathVariable String userId, @RequestBody User user) { }

// Check request body
@Secured
@Owner(requestField = "authorId")
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) { }

// Custom bypass roles
@Secured
@Owner(field = "userId", bypassRoles = {"ADMIN", "SUPPORT"})
@GetMapping("/users/{userId}/tickets")
public List<Ticket> getTickets(@PathVariable String userId) { }
```

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `field` | String | "" | Path variable/param to check |
| `requestField` | String | "" | Request body field to check |
| `entityField` | String | "" | Response entity field to check |
| `principalField` | String | "id" | User field for comparison |
| `bypassRoles` | String[] | {"ADMIN"} | Roles that bypass check |
| `adminBypass` | boolean | true | Allow ADMIN to bypass |
| `allowNullOwner` | boolean | false | Allow null owner IDs |
| `message` | String | "You can only access your own resources" | Error message |

### @RateLimit

Applies rate limiting to endpoints.

```java
// 100 requests per minute
@RateLimit(requests = 100, window = 60)
@GetMapping("/api/data")
public Data getData() { }

// Per user limiting
@RateLimit(requests = 10, window = 60, perUser = true)
@PostMapping("/messages")
public Message sendMessage(@RequestBody Message message) { }

// Login endpoint - strict limiting
@RateLimit(requests = 5, window = 300, key = "ip")
@PostMapping("/login")
public Token login(@RequestBody LoginRequest request) { }
```

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `requests` | int | - | Max requests in window |
| `window` | int | - | Time window in seconds |
| `key` | String | "ip" | Rate limit key (ip, user, token) |
| `perUser` | boolean | false | Limit per authenticated user |
| `message` | String | "Rate limit exceeded..." | Error message |
| `statusCode` | int | 429 | HTTP status when exceeded |

### @Audit

Logs security events automatically.

```java
// Basic audit
@Audit
@Secured("ADMIN")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { }

// With custom action name
@Audit(action = "USER_DELETE")
@Secured("ADMIN")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { }

// Sensitive operation
@Audit(level = AuditLevel.SENSITIVE)
@Secured("ADMIN")
@PutMapping("/users/{id}/password")
public void resetPassword(@PathVariable Long id) { }

// Include parameters (exclude sensitive ones)
@Audit(includeParams = true, excludeParams = {"password", "token"})
@PostMapping("/login")
public Token login(@RequestBody LoginRequest request) { }
```

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | String | "" | Custom action name |
| `level` | AuditLevel | NORMAL | Sensitivity level |
| `includeParams` | boolean | false | Log parameters |
| `excludeParams` | String[] | password, secret, token... | Params to exclude |
| `includeResponse` | boolean | false | Log response |
| `onlyOnSuccess` | boolean | false | Only log successful calls |
| `category` | String | "security" | Log category |

### @Cached

Security-aware response caching.

```java
// Cache per user for 60 seconds
@Cached(ttl = 60)
@Secured
@GetMapping("/profile")
public User getProfile() { }

// Global cache (public data)
@Cached(ttl = 300, perUser = false)
@Public
@GetMapping("/products")
public List<Product> getProducts() { }

// Cache per role
@Cached(ttl = 120, perRole = true)
@Secured({"ADMIN", "MANAGER"})
@GetMapping("/reports")
public List<Report> getReports() { }

// Conditional caching
@Cached(ttl = 60, condition = "#result != null")
@Secured
@GetMapping("/data")
public Data getData() { }
```

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `ttl` | int | 60 | Time-to-live in seconds |
| `enabled` | boolean | true | Enable caching |
| `perUser` | boolean | true | Cache per user |
| `perRole` | boolean | false | Cache per role |
| `key` | String | "" | Custom cache key |
| `condition` | String | "" | SpEL cache condition |
| `unless` | String | "" | SpEL unless condition |

### @Login, @Register, @RefreshToken

Auto-generate authentication endpoints.

```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    // Auto-generated login endpoint
    @Login(
        userService = UserService.class,
        findMethod = "findByUsername",
        claims = {"email", "displayName"}
    )
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return null; // Body is ignored
    }

    // Auto-generated registration endpoint
    @Register(
        userService = UserService.class,
        createMethod = "createUser",
        autoLogin = true
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        return null; // Body is ignored
    }

    // Auto-generated token refresh endpoint
    @RefreshToken
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        return null; // Body is ignored
    }
}
```

### @Authenticatable

Marks an entity as authenticatable.

```java
@Authenticatable(
    usernameField = "email",
    passwordField = "passwordHash",
    rolesField = "roles",
    idField = "id",
    claimFields = {"displayName", "department"}
)
@Entity
public class User {
    private Long id;
    private String email;
    private String passwordHash;
    private Set<String> roles;
    private String displayName;
    private String department;
    // getters...
}
```

---

## Facades Reference

### Auth Facade

Static access to authentication context from anywhere in your code.

```java
import ao.sudojed.lss.facade.Auth;

// Check authentication
if (Auth.check()) {
    // User is authenticated
}

if (Auth.guest()) {
    // User is NOT authenticated
}

// Get current user
LazyUser user = Auth.user();
String userId = Auth.id();
String username = Auth.username();

// Check roles
if (Auth.hasRole("ADMIN")) { }
if (Auth.hasAnyRole("ADMIN", "MANAGER")) { }
if (Auth.hasAllRoles("VERIFIED", "PREMIUM")) { }
if (Auth.isAdmin()) { }

// Check permissions
if (Auth.can("posts:write")) { }
if (Auth.cannot("users:delete")) { }

// Get claims
Object email = Auth.claim("email");
String dept = Auth.claim("department", "default");

// Require authentication (throws if not)
Auth.requireAuth();
Auth.requireRole("ADMIN");

// Login/Logout
Auth.login(lazyUser);
Auth.logout();

// Token revocation
Auth.revokeCurrentToken();
Auth.revokeAllTokens();
Auth.revokeTokensForUser("user-123");

// Password utilities
String hash = Auth.hashPassword("plainPassword");
boolean valid = Auth.checkPassword("plainPassword", hash);

// Execute as another user (testing)
Auth.runAs(testUser, () -> {
    // Code runs as testUser
    return someResult;
});

// Conditional execution
Auth.ifAuthenticated(user -> {
    System.out.println("Hello, " + user.getUsername());
});

Auth.ifGuest(() -> {
    System.out.println("Please log in");
});
```

### Guard Facade

Imperative authorization checks.

```java
import ao.sudojed.lss.facade.Guard;

// Require authentication
Guard.authenticated();

// Require specific role
Guard.role("ADMIN");

// Require any of these roles
Guard.anyRole("ADMIN", "MANAGER");

// Require all roles
Guard.allRoles("VERIFIED", "PREMIUM");

// Require admin
Guard.admin();

// Require permission
Guard.permission("users:delete");

// Check ownership
Guard.owner(resourceOwnerId);  // Admin auto-bypass

// Fluent API
Guard.check()
    .authenticated()
    .role("ADMIN")
    .permission("users:manage")
    .authorize();

// Conditional authorization
Guard.check()
    .role("MANAGER")
    .condition(() -> someBusinessLogic())
    .authorize();
```

---

## Advanced Topics

### Custom JWT Provider

Implement your own JWT provider:

```java
@Component
public class CustomJwtProvider implements JwtProvider {

    @Override
    public String createAccessToken(LazyUser user) {
        // Your implementation
    }

    @Override
    public String createRefreshToken(LazyUser user) {
        // Your implementation
    }

    @Override
    public Optional<LazyUser> validateToken(String token) {
        // Your implementation
    }

    @Override
    public Optional<LazyUser> refreshToken(String refreshToken) {
        // Your implementation
    }
}
```

### Token Revocation

Enable token blacklisting for logout functionality:

```java
@Configuration
public class SecurityConfig {

    @Bean
    public TokenBlacklist tokenBlacklist() {
        return new InMemoryTokenBlacklist();
    }

    @PostConstruct
    public void configureAuth() {
        Auth.setTokenBlacklist(tokenBlacklist());
    }
}

// Usage
@PostMapping("/logout")
public ResponseEntity<?> logout() {
    Auth.revokeCurrentToken();
    return ResponseEntity.ok(Map.of("message", "Logged out"));
}

@PostMapping("/logout-all")
public ResponseEntity<?> logoutAll() {
    Auth.revokeAllTokens();
    return ResponseEntity.ok(Map.of("message", "Logged out from all devices"));
}
```

### SpEL Conditions

Use Spring Expression Language in @Secured:

```java
// User can only access their own resources
@Secured(condition = "#userId == #principal.id")
@GetMapping("/users/{userId}/settings")
public Settings getSettings(@PathVariable String userId) { }

// Admin or owner
@Secured(condition = "#principal.isAdmin() or #userId == #principal.id")
@GetMapping("/users/{userId}/data")
public Data getData(@PathVariable String userId) { }

// Check claims
@Secured(condition = "#principal.getClaim('level', 0) >= 5")
@GetMapping("/advanced-features")
public Features getAdvancedFeatures() { }

// Complex conditions
@Secured(condition = "#amount < 1000 or #principal.hasRole('MANAGER')")
@PostMapping("/transfers")
public Transfer createTransfer(@RequestParam Integer amount) { }
```

**Available SpEL Variables:**
- `#principal` / `#user` - Current LazyUser
- `#authentication` - Same as principal
- `#paramName` - Method parameters by name
- `#target` / `#this` - Controller instance
- `#method` - Method object
- `#methodName` - Method name string

### Annotation Inheritance

Method-level annotations combine with class-level:

```java
@Secured("USER")  // All methods require USER role
@RestController
public class UserController {

    @GetMapping("/profile")  // Inherits @Secured("USER")
    public User getProfile() { }

    @Secured("ADMIN")  // Requires USER + ADMIN (combined)
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) { }
}
```

### Error Handling

Customize error responses:

```java
@ControllerAdvice
public class CustomSecurityExceptionHandler {

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<?> handleUnauthorized(UnauthorizedException ex) {
        return ResponseEntity.status(401).body(Map.of(
            "error", "UNAUTHORIZED",
            "message", ex.getMessage(),
            "timestamp", Instant.now()
        ));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(403).body(Map.of(
            "error", "FORBIDDEN",
            "message", ex.getMessage(),
            "timestamp", Instant.now()
        ));
    }
}
```

---

## Examples

### REST API with JWT

Complete example of a JWT-protected REST API:

```java
@EnableLazySecurity(
    jwt = @JwtConfig(secret = "${JWT_SECRET}"),
    publicPaths = {"/auth/**", "/health"}
)
@SpringBootApplication
public class Application { }

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Public
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return userService.findByUsername(request.username())
            .filter(user -> Auth.checkPassword(request.password(), user.getPasswordHash()))
            .map(user -> {
                LazyUser lazyUser = LazyUser.builder()
                    .id(user.getId())
                    .username(user.getUsername())
                    .roles(user.getRoles().toArray(new String[0]))
                    .build();
                TokenPair tokens = jwtService.createTokens(lazyUser);
                return ResponseEntity.ok(tokens.toMap());
            })
            .orElse(ResponseEntity.status(401).body(Map.of(
                "error", "Invalid credentials"
            )));
    }
}

@RestController
@RequestMapping("/api")
public class ApiController {

    @Secured
    @GetMapping("/profile")
    public Map<String, Object> getProfile() {
        return Map.of(
            "id", Auth.id(),
            "username", Auth.username(),
            "roles", Auth.user().getRoles()
        );
    }

    @Secured("ADMIN")
    @GetMapping("/users")
    public List<User> listUsers() {
        return userService.findAll();
    }
}
```

### Role-Based Access Control

```java
@RestController
@RequestMapping("/api")
public class RbacController {

    // Any authenticated user
    @Secured
    @GetMapping("/dashboard")
    public Dashboard getDashboard() { }

    // Only managers or admins
    @Secured({"MANAGER", "ADMIN"})
    @GetMapping("/reports")
    public List<Report> getReports() { }

    // Only users with BOTH roles
    @Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
    @GetMapping("/premium")
    public PremiumContent getPremiumContent() { }

    // Permission-based
    @Secured(permissions = "documents:export")
    @GetMapping("/documents/export")
    public byte[] exportDocuments() { }
}
```

### Resource Ownership

```java
@RestController
@RequestMapping("/api/users/{userId}")
public class UserResourceController {

    // User can only access their own orders
    @Secured
    @Owner(field = "userId")
    @GetMapping("/orders")
    public List<Order> getOrders(@PathVariable String userId) { }

    // User can only update their own profile, admin can update any
    @Secured
    @Owner(field = "userId", adminBypass = true)
    @PutMapping("/profile")
    public User updateProfile(
        @PathVariable String userId,
        @RequestBody UpdateProfileRequest request
    ) { }

    // Support staff can also access
    @Secured
    @Owner(field = "userId", bypassRoles = {"ADMIN", "SUPPORT"})
    @GetMapping("/tickets")
    public List<Ticket> getTickets(@PathVariable String userId) { }
}
```

### Rate Limiting

```java
@RestController
@RequestMapping("/api")
public class RateLimitedController {

    // General API limit
    @RateLimit(requests = 100, window = 60)
    @Secured
    @GetMapping("/data")
    public Data getData() { }

    // Strict limit for login
    @RateLimit(requests = 5, window = 300, key = "ip")
    @Public
    @PostMapping("/login")
    public Token login(@RequestBody LoginRequest request) { }

    // Per-user limit for expensive operations
    @RateLimit(requests = 10, window = 3600, perUser = true)
    @Secured
    @PostMapping("/reports/generate")
    public Report generateReport() { }
}
```

---

## Migration Guide

### From Spring Security

**Before (Spring Security):**

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
}

@RestController
public class MyController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public List<User> getUsers() { }
}
```

**After (LazySpringSecurity):**

```java
@EnableLazySecurity(
    jwt = @JwtConfig(secret = "${JWT_SECRET}"),
    publicPaths = {"/api/public/**"}
)
@SpringBootApplication
public class MyApplication { }

@RestController
public class MyController {
    
    @Secured("ADMIN")
    @GetMapping("/admin/users")
    public List<User> getUsers() { }
}
```

---

## Troubleshooting

### Common Issues

#### 1. "JWT_SECRET not configured"

**Solution:** Set the JWT secret in environment or application.yml:

```yaml
lazy-security:
  jwt:
    secret: ${JWT_SECRET:your-secret-key-at-least-32-characters}
```

#### 2. "401 Unauthorized" on all requests

**Possible causes:**
- Token not sent in Authorization header
- Token prefix mismatch (should be "Bearer ")
- Token expired
- Invalid token signature

**Debug:**
```yaml
lazy-security:
  debug: true
```

#### 3. CORS errors

**Solution:** Configure CORS in @EnableLazySecurity:

```java
@EnableLazySecurity(
    corsEnabled = true,
    corsOrigins = {"http://localhost:3000"}
)
```

#### 4. @Secured not working

**Check:**
- Is the annotation on a public method?
- Is the class a Spring-managed bean?
- Is AspectJ auto-proxy enabled?

### Debug Mode

Enable comprehensive logging:

```java
@EnableLazySecurity(debug = true)
```

Or in application.yml:

```yaml
lazy-security:
  debug: true

logging:
  level:
    ao.sudojed.lss: DEBUG
    AUDIT: INFO
```

### Logging Configuration

Configure logging in `logback-spring.xml`:

```xml
<configuration>
    <!-- Security logs -->
    <logger name="ao.sudojed.lss" level="DEBUG"/>
    
    <!-- Audit logs to separate file -->
    <appender name="AUDIT_FILE" class="ch.qos.logback.core.FileAppender">
        <file>logs/audit.log</file>
        <encoder>
            <pattern>%d{ISO8601} %msg%n</pattern>
        </encoder>
    </appender>
    
    <logger name="AUDIT" level="INFO" additivity="false">
        <appender-ref ref="AUDIT_FILE"/>
    </logger>
</configuration>
```

---

## Support

- **GitHub Issues:** [Report bugs and request features](https://github.com/jedin01/ls2/issues)
- **Documentation:** [ARCHITECTURE.md](ARCHITECTURE.md)

---

**Made with ❤️ by Sudojed Team**