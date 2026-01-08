# LazySpringSecurity (LSS)

**Zero-configuration security for Spring Boot APIs**

[![JitPack](https://jitpack.io/v/jedin01/ls2.svg)](https://jitpack.io/#jedin01/ls2)

Transform complex Spring Security configurations into simple, readable annotations. LSS follows **Convention over Configuration** principles, eliminating the need for countless configuration files, JWT setup, encoders, filters, and middleware - everything works out of the box.

## Why LSS?

**Traditional Spring Security requires multiple files:**

```
📁 src/main/java/security/
├── SecurityConfig.java         (50+ lines)
├── JwtAuthenticationFilter.java
├── JwtTokenProvider.java
├── JwtAuthenticationEntryPoint.java
├── UserDetailsServiceImpl.java
├── PasswordEncoderConfig.java
├── CorsConfig.java
└── WebSecurityConfig.java

📁 src/main/resources/
└── application.yml/properties  (50+ lines JWT, CORS, CSRF config)
```

```java
@Configuration
@EnableWebSecurity
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
                .anyRequest().authenticated())
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
    // + JwtDecoder, PasswordEncoder, AuthenticationManager, etc.
}
```

**With LazySpringSecurity (Convention over Configuration):**

```
📁 src/main/java/
└── MyController.java           (Clean business logic)

📁 src/main/resources/
└── application.yml/properties  (5 lines of config)
```

```java
@RestController
public class ApiController {
    
    @Public  // No SecurityConfig needed
    @GetMapping("/api/public/data")
    public Data getPublicData() { }
    
    @Secured("ADMIN")  // No role configuration needed
    @DeleteMapping("/api/admin/users/{id}")
    public void deleteUser(@PathVariable Long id) { }
    
    @Owner(field = "userId")  // No ownership logic needed
    @GetMapping("/api/users/{userId}/profile")
    public Profile getProfile(@PathVariable Long userId) { }
}
```

**Result: 90% fewer files, 95% less configuration code!**

## Quick Start

### 1. Add Dependency

**Maven:**
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>ls2</artifactId>
    <version>v1.0.0</version>
</dependency>
```

**Gradle:**
```gradle
repositories {
    maven { url 'https://jitpack.io' }
}
implementation 'com.github.jedin01:ls2:v1.0.0'
```

### 2. Configure

**application.yml:**
```yaml
lss:
  jwt:
    secret: "your-256-bit-secret-key"
    expiration: 86400000  # 24 hours
  security:
    enabled: true
    cors:
      allowed-origins: ["http://localhost:3000"]
```

**application.properties:**
```properties
lss.jwt.secret=your-256-bit-secret-key
lss.jwt.expiration=86400000
lss.security.enabled=true
lss.security.cors.allowed-origins=http://localhost:3000
```

> Choose your preferred format - both work identically with LSS!

### 3. Secure Your APIs

```java
@RestController
public class MyController {
    
    // Public endpoint
    @Public
    @GetMapping("/health")
    public String health() {
        return "OK";
    }
    
    // Requires authentication
    @Secured
    @GetMapping("/profile")
    public User getProfile(Principal principal) {
        return userService.findByUsername(principal.getName());
    }
    
    // Admin only
    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
    
    // Multiple roles
    @Secured({"ADMIN", "MODERATOR"})
    @PostMapping("/moderate")
    public void moderateContent(@RequestBody Content content) {
        contentService.moderate(content);
    }
    
    // Owner verification
    @Owner(field = "userId")
    @GetMapping("/users/{userId}/settings")
    public Settings getUserSettings(@PathVariable Long userId) {
        return settingsService.findByUserId(userId);
    }
    
    // Rate limiting
    @RateLimit(requests = 100, window = 60)
    @PostMapping("/process")
    public Result processData(@RequestBody DataRequest request) {
        return dataService.process(request);
    }
    
    // Audit logging
    @Audit(action = "USER_DELETION", level = Audit.AuditLevel.CRITICAL)
    @Secured("ADMIN")
    @DeleteMapping("/admin/users/{id}")
    public void adminDeleteUser(@PathVariable Long id) {
        userService.adminDelete(id);
    }
}
```

## Key Features

### 🛡️ **Security Annotations**
- `@Public` - No authentication required
- `@Secured` - Role-based access control with advanced conditions
- `@Owner` - Resource ownership verification
- `@RateLimit` - Request rate limiting
- `@Audit` - Automatic security event logging

### ⚡ **Performance**
- `@Cached` - Security-aware intelligent caching
- Built-in rate limiting and DDoS protection
- Optimized JWT processing

### 🔧 **Convention over Configuration**
- **Zero configuration files** - No SecurityConfig, JwtFilter, CorsConfig, etc.
- **Auto-configured JWT** - Token generation, validation, refresh built-in
- **Smart defaults** - Production-ready security out of the box
- **Override when needed** - Sensible defaults, customizable when required
- **One dependency** - Replaces 10+ security-related dependencies

### 🚀 **What You Get For Free**
- **JWT complete setup** - Generation, validation, refresh, blacklisting
- **Password encryption** - BCrypt encoder with salt
- **CORS handling** - Smart origin detection and configuration  
- **Security headers** - CSRF, XSS, clickjacking protection
- **Rate limiting** - DDoS protection and abuse prevention
- **Audit logging** - Security events tracking
- **Error handling** - Consistent security error responses

## Advanced Usage

### Dynamic Authorization
```java
@Secured(condition = "#userId == principal.id or hasRole('ADMIN')")
@PutMapping("/users/{userId}")
public User updateUser(@PathVariable Long userId, @RequestBody User user) {
    return userService.update(userId, user);
}
```

### Permission-Based Access
```java
@Secured(permissions = {"users:read", "users:write"})
@PostMapping("/users")
public User createUser(@RequestBody CreateUserRequest request) {
    return userService.create(request);
}
```

### Automated Login Endpoints
```java
@Login(
    userService = UserService.class,
    findMethod = "findByEmail"
)
@PostMapping("/auth/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // Implementation generated automatically
}
```

## What LSS Replaces

### ❌ Files You Don't Need Anymore:
```java
// ❌ SecurityConfig.java
// ❌ JwtAuthenticationFilter.java  
// ❌ JwtTokenProvider.java
// ❌ JwtAuthenticationEntryPoint.java
// ❌ UserDetailsServiceImpl.java
// ❌ PasswordEncoderConfig.java
// ❌ CorsConfig.java
// ❌ WebSecurityConfig.java
// ❌ AuthenticationManagerConfig.java
// ❌ JwtUtils.java
```

### ✅ What You Get Instead:
- **One dependency** - `com.github.jedin01:ls2`
- **Five lines of YAML** - Basic JWT configuration
- **Clean annotations** - Security logic where it belongs
- **Zero boilerplate** - Convention over Configuration in action

### 🎯 Enterprise Features
- **Multi-tenant support** - Isolated security contexts
- **Integration ready** - LDAP, OAuth2, SAML connectors
- **Compliance built-in** - GDPR, SOX, HIPAA patterns
- **Observability** - Metrics, tracing, security dashboards
- **Performance** - Sub-millisecond authorization decisions

## Documentation

- [📖 Complete Annotation Guide](ANNOTATIONS_GUIDE.md)
- [⚙️ Configuration Examples](CONFIGURATION_EXAMPLES.md) - YAML & Properties
- [🚀 JitPack Setup Guide](JITPACK_USAGE.md)
- [💡 Working Examples](example-project/)

## Community

- **Issues**: [GitHub Issues](https://github.com/jedin01/ls2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jedin01/ls2/discussions)
- **Email**: abner@sudojed.ao

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Transform your Spring Boot security from complex to simple. Get started with LSS today.** 🛡️