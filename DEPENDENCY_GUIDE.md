# LazySpringSecurity - Dependency Management Guide

## Dependency Model (v1.2.0+)

### What Changed?

Starting with version 1.2.0, LazySpringSecurity follows Spring Boot best practices by making non-essential dependencies **optional**. This gives you full control over your application's dependencies.

### Core Dependencies (Always Included)

These are automatically added when you include LSS:

```xml
✅ spring-boot-starter-security  (Core security)
✅ spring-boot-starter-aop       (Aspect-oriented security)
✅ jjwt-api, jjwt-impl          (JWT support)
```

### Optional Dependencies (You Choose)

These are **NOT** automatically added. Add them based on your needs:

```xml
⚪ spring-boot-starter-web        (For REST APIs, controllers)
⚪ spring-boot-starter-validation (For @Valid annotations)
⚪ spring-boot-starter-cache      (For @Cached annotation)
⚪ spring-boot-starter-data-redis (For distributed features)
```

---

## Usage Scenarios

### Scenario 1: REST API with JWT Authentication

**What you need:**
- LSS for security
- Spring Web for REST endpoints

```xml
<dependencies>
    <!-- LazySpringSecurity Starter -->
    <dependency>
        <groupId>com.github.jedin01</groupId>
        <artifactId>lazy-spring-security-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
    
    <!-- Spring Web - Required for REST APIs -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

### Scenario 2: REST API + Validation

**What you need:**
- LSS for security
- Spring Web for REST endpoints
- Validation for request validation

```xml
<dependencies>
    <dependency>
        <groupId>com.github.jedin01</groupId>
        <artifactId>lazy-spring-security-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Validation - For @Valid on request bodies -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
</dependencies>
```

### Scenario 3: High-Performance API with Caching

**What you need:**
- LSS for security
- Spring Web for REST endpoints
- Cache for `@Cached` annotation

```xml
<dependencies>
    <dependency>
        <groupId>com.github.jedin01</groupId>
        <artifactId>lazy-spring-security-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Cache - For @Cached annotation -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
</dependencies>
```

### Scenario 4: Distributed Microservices

**What you need:**
- LSS for security
- Spring Web for REST endpoints
- Cache for `@Cached` annotation
- Redis for distributed rate limiting and caching

```xml
<dependencies>
    <dependency>
        <groupId>com.github.jedin01</groupId>
        <artifactId>lazy-spring-security-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
    
    <!-- Redis - For distributed features -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>
```

### Scenario 5: Non-Web Application (Scheduled Jobs, CLI)

**What you need:**
- Only LSS for JWT generation/validation
- No web dependencies!

```xml
<dependencies>
    <!-- LazySpringSecurity Starter - No web dependencies! -->
    <dependency>
        <groupId>com.github.jedin01</groupId>
        <artifactId>lazy-spring-security-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
</dependencies>
```

**Example usage:**
```java
@SpringBootApplication
@EnableLazySecurity(jwt = @JwtConfig(secret = "${JWT_SECRET}"))
public class BatchJobApplication {
    
    @Autowired
    private JwtProvider jwtProvider;
    
    @Scheduled(cron = "0 0 * * * *")
    public void processSecurely() {
        // Generate JWT for service-to-service auth
        String token = jwtProvider.generateAccessToken(
            LazyUser.builder()
                .id("service-account")
                .username("batch-processor")
                .roles(Set.of("SERVICE"))
                .build()
        );
        
        // Use token to call other services
        externalService.call(token);
    }
}
```

---

## Feature-to-Dependency Mapping

| LSS Feature | Required Dependencies |
|-------------|----------------------|
| `@Secured`, `@Public`, `@Owner` | Core only (included) |
| `@Login`, `@Register`, `@RefreshToken` | + spring-boot-starter-web |
| JWT generation/validation | Core only (included) |
| `@RateLimit` (IP-based) | + spring-boot-starter-web |
| `@RateLimit` (distributed) | + spring-boot-starter-web + redis |
| `@Cached` | + spring-boot-starter-cache |
| `@Cached` (distributed) | + spring-boot-starter-cache + redis |
| `@Audit` | Core only (included) |
| `@Valid` on request bodies | + spring-boot-starter-validation |
| `LazyUser` injection in controllers | + spring-boot-starter-web |

---

## Why This Change?

### Old Model (v1.0-1.1)
```xml
<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>lazy-spring-security-starter</artifactId>
    <version>1.1.0</version>
</dependency>
```

**Problems:**
- ❌ Forced Spring Web even for non-web apps
- ❌ Forced Tomcat embedded server (~10MB)
- ❌ Forced validation library
- ❌ Forced cache library
- ❌ Total: ~40 transitive dependencies

### New Model (v1.2.0+)
```xml
<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>lazy-spring-security-starter</artifactId>
    <version>1.2.0</version>
</dependency>
<!-- Add only what you need -->
```

**Benefits:**
- ✅ Only core security (~15 dependencies)
- ✅ You control web, cache, validation
- ✅ Smaller applications
- ✅ Faster startup
- ✅ Works in non-web contexts

---

## Migration from v1.1 to v1.2

### If You're Using Web Features

**Add this to your pom.xml:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

### If You're Using @Valid

**Add this to your pom.xml:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

### If You're Using @Cached

**Add this to your pom.xml:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-cache</artifactId>
</dependency>
```

### Complete Migration Example

**Before (v1.1):**
```xml
<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>lazy-spring-security-starter</artifactId>
    <version>1.1.0</version>
</dependency>
<!-- Everything included automatically -->
```

**After (v1.2):**
```xml
<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>lazy-spring-security-starter</artifactId>
    <version>1.2.0</version>
</dependency>

<!-- Explicitly add what you use -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-cache</artifactId>
</dependency>
```

---

## FAQ

### Q: Why make dependencies optional?

**A:** Following Spring Boot best practices. A starter should provide core functionality and let developers choose additional features. This approach:
- Reduces application size
- Improves startup time
- Allows LSS to work in non-web contexts (batch jobs, CLI tools)
- Follows principle of least surprise

### Q: What if I forget to add a dependency?

**A:** LSS will fail fast at startup with a clear error message:

```
***************************
APPLICATION FAILED TO START
***************************

Description:

LazySecurityWebAutoConfiguration requires spring-boot-starter-web dependency.

Action:

Add to your pom.xml:
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
```

### Q: Can I use LSS without Spring Web?

**A:** Yes! LSS core features (JWT generation/validation, security context) work without Spring Web. Perfect for:
- Scheduled jobs that need JWT
- CLI tools
- Message-driven applications
- gRPC services

### Q: Will my existing v1.1 apps break?

**A:** No! Just add the dependencies you were already using implicitly:
- REST API? Add `spring-boot-starter-web`
- Using `@Valid`? Add `spring-boot-starter-validation`
- Using `@Cached`? Add `spring-boot-starter-cache`

---

## Comparison with Spring Boot Starters

LSS now follows the same pattern as official Spring Boot starters:

| Starter | Forces Web? | Forces Validation? | Forces Cache? |
|---------|------------|-------------------|---------------|
| spring-boot-starter-security | ❌ No | ❌ No | ❌ No |
| spring-boot-starter-data-jpa | ❌ No | ❌ No | ❌ No |
| **lazy-spring-security-starter (v1.2+)** | ❌ No | ❌ No | ❌ No |
| lazy-spring-security-starter (v1.1) | ✅ Yes | ✅ Yes | ✅ Yes |

---

## Recommended Setup for New Projects

```xml
<!-- pom.xml -->
<dependencies>
    <!-- 1. LazySpringSecurity (core) -->
    <dependency>
        <groupId>com.github.jedin01</groupId>
        <artifactId>lazy-spring-security-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
    
    <!-- 2. Spring Web (if building REST API) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- 3. Validation (if using @Valid) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    
    <!-- 4. Cache (if using @Cached) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
    
    <!-- 5. Redis (optional, for distributed features) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>
```

This gives you full control over your application's dependencies while keeping the simplicity of LSS annotations.
