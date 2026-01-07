# LazySpringSecurity - Documentação Técnica

## Visão Geral

O **LazySpringSecurity (LSS)** é um framework que abstrai a complexidade do Spring Security, oferecendo uma DSL baseada em anotações para autenticação e autorização em aplicações Spring Boot.

### Motivação

O Spring Security é poderoso mas verboso. Configurar autenticação JWT requer:
- `SecurityFilterChain` com múltiplos configuradores
- Filtros customizados para extração de tokens
- `UserDetailsService` ou `AuthenticationProvider`
- Exception handlers para erros de autenticação
- Configuração manual de CORS/CSRF

O LSS reduz isso para uma única anotação: `@EnableLazySecurity`.

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                      Camada de Anotações                        │
│  @EnableLazySecurity  @Secured  @Public  @Owner  @RateLimit     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Auto-Configuração                            │
│              LazySecurityAutoConfiguration                       │
│    - Processa @EnableLazySecurity                               │
│    - Configura SecurityFilterChain                              │
│    - Registra beans (JwtProvider, Aspects, Filters)             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Camada de Filtros                          │
│                       LazyJwtFilter                             │
│    - Intercepta requests antes do Spring Security               │
│    - Extrai e valida JWT do header Authorization                │
│    - Popula LazySecurityContext com LazyUser                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Camada de Aspectos                         │
│           LazySecurityAspect    RateLimitAspect                 │
│    - Intercepta métodos anotados via AOP                        │
│    - Verifica roles, permissões, ownership                      │
│    - Lança exceções de segurança quando necessário              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Controller/Service                         │
│    - Recebe LazyUser injetado automaticamente                   │
│    - Acessa dados do usuário via LazySecurityContext            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Componentes Principais

### 1. Anotações (`ao.sudojed.lss.annotation`)

#### `@EnableLazySecurity`
Anotação principal que ativa o LSS. Usa `@Import` para carregar a configuração.

```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(LazySecurityAutoConfiguration.class)
public @interface EnableLazySecurity {
    String[] publicPaths() default {};
    JwtConfig jwt() default @JwtConfig;
    boolean corsEnabled() default true;
    boolean csrfEnabled() default false;
    boolean debug() default false;
}
```

**Mecanismo**: Implementa `ImportAware` para ler os atributos da anotação em tempo de execução e mesclar com `application.yml`.

#### `@Secured`
Anotação unificada para proteção de endpoints.

```java
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Secured {
    String[] value() default {};        // Roles (atalho)
    String[] roles() default {};        // Alias para value()
    String[] permissions() default {};
    boolean all() default false;        // false=ANY, true=ALL
    String message() default "Access denied";
    String condition() default "";      // SpEL expression
}
```

**Exemplos de uso:**
```java
@Secured                          // Qualquer usuário autenticado
@Secured("ADMIN")                 // Requer role ADMIN
@Secured({"ADMIN", "MANAGER"})    // Qualquer uma das roles
@Secured(value = {"A", "B"}, all = true)  // Todas as roles necessárias
```



#### `@Owner`
Verifica se o usuário é dono do recurso.

```java
public @interface Owner {
    String field();                    // Nome do parâmetro (ex: "userId")
    boolean adminBypass() default true; // Admin pode acessar qualquer recurso
}
```

#### `@Public`
Marca endpoint como público (sem autenticação).

```java
public @interface Public {
    String reason() default "";  // Documentação
}
```

---

### 2. Core (`ao.sudojed.lss.core`)

#### `LazyUser`
Representa o usuário autenticado. Imutável, construído via Builder.

```java
public class LazyUser {
    private final String id;
    private final String username;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> claims;
    private final boolean authenticated;
    
    // Métodos de verificação
    public boolean hasRole(String role);
    public boolean hasAnyRole(String... roles);
    public boolean hasAllRoles(String... roles);
    public boolean hasPermission(String permission);
    public boolean isAdmin();
    public <T> T getClaim(String key);
}
```

**Design Pattern**: Builder para construção fluente e imutabilidade para thread-safety.

#### `LazySecurityContext`
Armazena o usuário atual usando `ThreadLocal`.

```java
public class LazySecurityContext {
    private static final ThreadLocal<LazyUser> currentUser = new ThreadLocal<>();
    
    public static LazyUser getCurrentUser();
    public static void setCurrentUser(LazyUser user);
    public static void clear();
}
```

**Importante**: O filtro JWT popula o contexto no início do request e limpa no `finally`.

#### `LazySecurityProperties`
Configurações via `@ConfigurationProperties`.

```java
@ConfigurationProperties(prefix = "lazy-security")
public class LazySecurityProperties {
    private boolean enabled = true;
    private boolean debug = false;
    private List<String> publicPaths = new ArrayList<>();
    private Jwt jwt = new Jwt();
    private Cors cors = new Cors();
    
    public static class Jwt {
        private String secret;
        private long expiration = 3600000;      // 1 hora
        private long refreshExpiration = 604800000; // 7 dias
        private String issuer = "lazy-spring-security";
    }
}
```

---

### 3. JWT (`ao.sudojed.lss.jwt`)

#### `JwtProvider` (Interface)
Contrato para geração/validação de tokens.

```java
public interface JwtProvider {
    String generateToken(LazyUser user);
    String generateToken(LazyUser user, Map<String, Object> extraClaims);
    String generateRefreshToken(LazyUser user);
    LazyUser validateToken(String token);
    boolean isTokenValid(String token);
    String extractSubject(String token);
}
```

#### `DefaultJwtProvider`
Implementação usando JJWT (io.jsonwebtoken).

```java
public class DefaultJwtProvider implements JwtProvider {
    private final SecretKey secretKey;
    
    @Override
    public String generateToken(LazyUser user) {
        return Jwts.builder()
            .subject(user.getId())
            .claim("username", user.getUsername())
            .claim("roles", user.getRoles())
            .claim("permissions", user.getPermissions())
            .claim("type", "access")
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(secretKey, Jwts.SIG.HS384)
            .compact();
    }
}
```

**Algoritmo**: HS384 (HMAC-SHA384) - balanço entre segurança e performance.

#### `TokenPair`
Record que encapsula access + refresh tokens.

```java
public record TokenPair(
    String accessToken,
    String refreshToken,
    long expiresIn
) {
    public Map<String, Object> toMap() {
        return Map.of(
            "access_token", accessToken,
            "refresh_token", refreshToken,
            "token_type", "Bearer",
            "expires_in", expiresIn
        );
    }
}
```

---

### 4. Filtros (`ao.sudojed.lss.filter`)

#### `LazyJwtFilter`
Filtro que processa tokens JWT antes do Spring Security.

```java
public class LazyJwtFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) {
        try {
            String token = extractToken(request);
            
            if (token != null && jwtProvider.isTokenValid(token)) {
                LazyUser user = jwtProvider.validateToken(token);
                LazySecurityContext.setCurrentUser(user);
                
                // Configura Spring Security
                var auth = new UsernamePasswordAuthenticationToken(
                    user, null, toGrantedAuthorities(user.getRoles())
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            
            filterChain.doFilter(request, response);
        } finally {
            LazySecurityContext.clear();  // Limpa ThreadLocal
        }
    }
    
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}
```

**Fluxo**:
1. Extrai token do header `Authorization: Bearer <token>`
2. Valida assinatura e expiração
3. Reconstrói `LazyUser` a partir dos claims
4. Popula `LazySecurityContext` (nosso contexto)
5. Popula `SecurityContextHolder` (contexto do Spring Security)

---

### 5. Aspectos (`ao.sudojed.lss.aspect`)

#### `LazySecurityAspect`
Intercepta métodos anotados com `@Secured` e `@Owner`.

```java
@Aspect
@Order(100)
public class LazySecurityAspect {

    @Before("@annotation(ao.sudojed.lss.annotation.Secured) || " +
            "@within(ao.sudojed.lss.annotation.Secured)")
    public void checkSecured(JoinPoint joinPoint) {
        Secured annotation = getAnnotation(joinPoint, Secured.class);
        LazyUser user = LazySecurityContext.getCurrentUser();
        
        // 1. Verifica autenticação
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }
        
        // 2. Verifica roles (value() ou roles())
        String[] roles = annotation.value().length > 0 
            ? annotation.value() 
            : annotation.roles();
        if (roles.length > 0) {
            boolean hasRole = annotation.all() 
                ? user.hasAllRoles(roles) 
                : user.hasAnyRole(roles);
            if (!hasRole) {
                throw new AccessDeniedException(annotation.message());
            }
        }
        
        // 3. Verifica permissões
        // ...
    }
    
    @Before("@annotation(ao.sudojed.lss.annotation.Owner)")
    public void checkOwnership(JoinPoint joinPoint) {
        Owner annotation = getAnnotation(joinPoint, Owner.class);
        LazyUser user = LazySecurityContext.getCurrentUser();
        
        // Admin bypass
        if (annotation.adminBypass() && user.isAdmin()) {
            return;
        }
        
        // Extrai valor do campo (ex: @PathVariable userId)
        Object fieldValue = extractFieldValue(joinPoint, annotation.field());
        
        if (!user.getId().equals(String.valueOf(fieldValue))) {
            throw new AccessDeniedException("You can only access your own resources");
        }
    }
}
```

**AOP Pointcuts**:
- `@annotation()` - intercepta métodos anotados
- `@within()` - intercepta métodos de classes anotadas

---

### 6. Facades (`ao.sudojed.lss.facade`)

Facades fornecem acesso estático ao contexto de segurança sem injeção de dependência.

#### `Auth` - Acesso ao Usuário Autenticado

Facade estática para acessar informações do usuário atual:

```java
import ao.sudojed.lss.facade.Auth;

// Acesso direto
String userId = Auth.id();
String username = Auth.username();
String email = Auth.claim("email");
Set<String> roles = Auth.user().getRoles();

// Verificações
boolean isAdmin = Auth.isAdmin();
boolean isGuest = Auth.guest();

// Hashing de senha (BCrypt)
String hash = Auth.hashPassword("plainPassword");
boolean valid = Auth.checkPassword("plainPassword", hash);
```

**Implementação**:
```java
public final class Auth {
    private Auth() {}  // Utility class
    
    public static LazyUser user() {
        return LazySecurityContext.getCurrentUser();
    }
    
    public static String id() {
        return user().getId();
    }
    
    public static boolean isAdmin() {
        return user().isAdmin();
    }
    
    public static boolean guest() {
        return !user().isAuthenticated();
    }
    
    public static String hashPassword(String rawPassword) {
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt());
    }
    
    public static boolean checkPassword(String rawPassword, String hashedPassword) {
        return BCrypt.checkpw(rawPassword, hashedPassword);
    }
}
```

#### `Guard` - Verificações Imperativas

Facade para validações de autorização:

```java
import ao.sudojed.lss.facade.Guard;

// Verificações simples (lança AccessDeniedException)
Guard.admin();              // Requer role ADMIN
Guard.role("MANAGER");      // Requer role específica
Guard.anyRole("ADMIN", "MODERATOR");  // Requer qualquer role
Guard.owner(userId);        // Verifica ownership

// API fluente
Guard.check()
    .role("ADMIN")
    .permission("data:read")
    .authorize();
```

**Implementação**:
```java
public final class Guard {
    private Guard() {}
    
    public static void admin() {
        if (!Auth.isAdmin()) {
            throw new AccessDeniedException("Admin role required");
        }
    }
    
    public static void role(String role) {
        if (!Auth.user().hasRole(role)) {
            throw new AccessDeniedException("Role " + role + " required");
        }
    }
    
    public static void anyRole(String... roles) {
        if (!Auth.user().hasAnyRole(roles)) {
            throw new AccessDeniedException("One of roles required: " + Arrays.toString(roles));
        }
    }
    
    public static void owner(String resourceOwnerId) {
        if (Auth.isAdmin()) return; // Admin bypass
        if (!Auth.id().equals(resourceOwnerId)) {
            throw new AccessDeniedException("You can only access your own resources");
        }
    }
    
    public static GuardBuilder check() {
        return new GuardBuilder();
    }
}
```

**Quando usar Facades vs Anotações**:

| Caso de Uso | Abordagem |
|-------------|-----------|
| Proteção simples de endpoint | Anotação (`@Secured`, `@Secured("ADMIN")`) |
| Lógica condicional de autorização | `Guard` facade |
| Acesso a dados do usuário em service | `Auth` facade |
| Validação de ownership em método | `@Owner` ou `Guard.owner()` |

---

### 7. Exceções (`ao.sudojed.lss.exception`)

Hierarquia de exceções:

```
LazySecurityException (base)
├── UnauthorizedException (401)
├── AccessDeniedException (403)
└── RateLimitExceededException (429)
```

#### `LazySecurityControllerAdvice`
Converte exceções em respostas HTTP.

```java
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LazySecurityControllerAdvice {

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<Map<String, Object>> handleUnauthorized(UnauthorizedException ex) {
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body(errorResponse(401, "UNAUTHORIZED", ex.getMessage()));
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity
            .status(HttpStatus.FORBIDDEN)
            .body(errorResponse(403, "ACCESS_DENIED", ex.getMessage()));
    }
}
```

---

### 8. Auto-Configuração (`ao.sudojed.lss.config`)

#### `LazySecurityAutoConfiguration`
Configura todo o framework.

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(LazySecurityProperties.class)
public class LazySecurityAutoConfiguration implements ImportAware, WebMvcConfigurer {

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        // Lê atributos de @EnableLazySecurity
        Map<String, Object> attrs = importMetadata.getAnnotationAttributes(
            EnableLazySecurity.class.getName()
        );
        // Mescla com properties do application.yml
        mergeAnnotationWithProperties();
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
            .csrf(csrf -> properties.isCsrfEnabled() ? csrf : csrf.disable())
            .cors(cors -> properties.getCors().isEnabled() ? 
                cors.configurationSource(corsConfigurationSource()) : 
                cors.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                // Public paths
                for (String path : properties.getPublicPaths()) {
                    auth.requestMatchers(path).permitAll();
                }
                auth.anyRequest().authenticated();
            })
            .addFilterBefore(lazyJwtFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(exceptionHandler)
                .accessDeniedHandler(exceptionHandler));
        
        return http.build();
    }
    
    @Bean
    public LazySecurityAspect lazySecurityAspect() {
        return new LazySecurityAspect();
    }
    
    @Bean
    @ConditionalOnMissingBean
    public JwtProvider jwtProvider() {
        return new DefaultJwtProvider(properties);
    }
}
```

**Spring Boot Auto-Configuration**:
Registrado em `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

---

## Fluxo de Execução

### Request Autenticado

```
1. Request: GET /api/profile
   Header: Authorization: Bearer eyJ...

2. LazyJwtFilter
   ├── Extrai token do header
   ├── Valida token (assinatura + expiração)
   ├── Reconstrói LazyUser dos claims
   ├── LazySecurityContext.setCurrentUser(user)
   └── SecurityContextHolder.setAuthentication(...)

3. Spring Security FilterChain
   └── Permite acesso (usuário autenticado)

4. LazySecurityAspect (AOP)
   ├── @Secured encontrado no método
   ├── Verifica user.isAuthenticated() ✓
   ├── Verifica roles (se especificadas)
   └── Permite execução

5. Controller
   ├── LazyUser injetado via LazyUserArgumentResolver
   └── Executa lógica de negócio

6. Response: 200 OK
```

### Request Não Autenticado para Rota Protegida

```
1. Request: GET /api/profile
   (sem header Authorization)

2. LazyJwtFilter
   └── Token não encontrado, continua sem autenticar

3. Spring Security FilterChain
   └── Bloqueia: anyRequest().authenticated()

4. LazySecurityExceptionHandler
   └── Retorna 401 Unauthorized
```

### Request com Role Insuficiente

```
1. Request: GET /api/admin/users
   Header: Authorization: Bearer eyJ... (user com role USER)

2. LazyJwtFilter
   └── Token válido, user populado

3. Spring Security FilterChain
   └── Permite (usuário autenticado)

4. LazySecurityAspect (AOP)
   ├── @Secured("ADMIN") encontrado no método
   ├── Verifica user.hasRole("ADMIN") ✗
   └── throw AccessDeniedException

5. LazySecurityControllerAdvice
   └── Retorna 403 Forbidden
```

---

## Extensibilidade

### Custom JwtProvider

```java
@Bean
public JwtProvider jwtProvider() {
    return new CustomJwtProvider();  // Sua implementação
}
```

### Adicionar Claims ao Token

```java
LazyUser user = LazyUser.builder()
    .id("123")
    .username("john")
    .roles("USER")
    .claim("departamento", "TI")
    .claim("nivel", 5)
    .build();

// Recuperar no controller:
String dept = user.getClaim("departamento");
```

### Custom SecurityFilterChain

Se precisar de configuração avançada, crie seu próprio bean:

```java
@Bean
public SecurityFilterChain customFilterChain(HttpSecurity http) {
    // Sua configuração personalizada
}
```

---

## Testes

### Testando Endpoints Protegidos

```java
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class SecurityTest {

    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private JwtService jwtService;
    
    @Test
    void protectedEndpoint_withValidToken_returns200() {
        LazyUser user = LazyUser.builder()
            .id("1").username("test").roles("USER").build();
        String token = jwtService.createAccessToken(user);
        
        mockMvc.perform(get("/api/profile")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
    
    @Test
    void adminEndpoint_withUserRole_returns403() {
        LazyUser user = LazyUser.builder()
            .id("1").username("test").roles("USER").build();
        String token = jwtService.createAccessToken(user);
        
        mockMvc.perform(get("/api/admin/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }
}
```

### Demo Application Tests

O projeto inclui uma demo application completa com **73 testes** que demonstram todas as funcionalidades do LSS:

| Classe de Teste | Qtd | Cobertura |
|-----------------|-----|-----------|
| `AuthControllerTest` | 10 | Register, Login, Refresh tokens, Error cases |
| `ProfileControllerTest` | 9 | Profile CRUD, LazyUser injection, Auth facade |
| `AdminControllerTest` | 20 | @Secured("ADMIN"), role checks, user management, dashboard |
| `OrderControllerTest` | 15 | @Owner, @Secured with multiple roles, CRUD, authorization |
| `SimpleAuthControllerTest` | 5 | Public endpoints, annotation variants |
| `UserServiceTest` | 14 | Service layer, password hashing, role management |
| `SecuredAnnotationTest` | 15 | @Secured annotation, migration from deprecated annotations |

Executar os testes:

```bash
# Todos os testes
./mvnw test

# Apenas testes da demo
./mvnw test -Dtest="ao.sudojed.lss.demo.**"

# Testes específicos
./mvnw test -Dtest="AdminControllerTest"
```

---

## Demo Application

A demo em `ao.sudojed.lss.demo` demonstra casos de uso reais do LSS.

### Estrutura

```
demo/
├── DemoApplication.java      # Main class com @EnableLazySecurity
├── controller/
│   ├── AuthController.java   # @Login, @Register, @RefreshToken
│   ├── ProfileController.java # LazyUser injection, Auth facade
│   ├── AdminController.java  # @Secured("ADMIN"), Guard facade
│   ├── OrderController.java  # @Owner, resource-level security
│   └── SimpleAuthController.java # Simplified annotations
├── service/
│   └── UserService.java      # In-memory user storage, Auth.hashPassword()
├── model/
│   ├── User.java             # User entity
│   └── Order.java            # Order entity
└── dto/
    └── ...                   # DTOs para request/response
```

### Fluxo de Autenticação

```
1. POST /auth/register
   └── Cria usuário com senha hasheada (Auth.hashPassword)
   
2. POST /auth/login
   └── Valida credenciais, gera TokenPair (access + refresh)
   
3. GET /api/profile (com Bearer token)
   └── LazyJwtFilter valida token
   └── LazySecurityContext.setCurrentUser()
   └── Controller recebe LazyUser ou usa Auth facade
   
4. POST /auth/refresh
   └── JwtService.refresh() gera novo TokenPair
```

### Exemplos de Uso

**Controller com LazyUser injetado:**
```java
@GetMapping("/profile")
@Secured
public Map<String, Object> getProfile(LazyUser user) {
    return Map.of(
        "id", user.getId(),
        "username", user.getUsername(),
        "roles", user.getRoles()
    );
}
```

**Controller com Auth facade:**
```java
@GetMapping("/me")
@Secured
public Map<String, Object> me() {
    return Map.of(
        "id", Auth.id(),
        "username", Auth.username(),
        "isAdmin", Auth.isAdmin()
    );
}
```

**Proteção por role:**
```java
@GetMapping("/users")
@Secured("ADMIN")  // Apenas ADMIN
public List<User> listUsers() { ... }

@GetMapping("/reports")
@Secured({"ADMIN", "MANAGER"})  // ADMIN ou MANAGER
public Map<String, Object> reports() { ... }
```

**Proteção por ownership:**
```java
@GetMapping("/users/{userId}/orders")
@Owner(field = "userId")  // Usuário só acessa próprios recursos (admin bypass)
public List<Order> getUserOrders(@PathVariable String userId) { ... }
```

---

## Configuração de Produção

### application-prod.yml

```yaml
lazy-security:
  debug: false
  jwt:
    secret: ${JWT_SECRET}  # Via variável de ambiente
    expiration: 900000     # 15 minutos
    refresh-expiration: 86400000  # 24 horas
    issuer: minha-api-producao
  cors:
    enabled: true
    origins:
      - https://meusite.com
    allow-credentials: true
```

### Variáveis de Ambiente

```bash
export JWT_SECRET="chave-de-256-bits-ou-mais-para-producao"
```

---

## Estrutura de Pacotes

```
ao.sudojed.lss/
├── annotation/           # Anotações públicas
│   ├── EnableLazySecurity.java
│   ├── JwtConfig.java
│   ├── Secured.java
│   ├── Public.java
│   ├── Owner.java
│   ├── Login.java
│   ├── Register.java
│   ├── RefreshToken.java
│   └── RateLimit.java
├── core/                 # Classes principais
│   ├── LazyUser.java
│   ├── LazySecurityContext.java
│   └── LazySecurityProperties.java
├── jwt/                  # Componentes JWT
│   ├── JwtProvider.java
│   ├── DefaultJwtProvider.java
│   ├── JwtService.java
│   └── TokenPair.java
├── filter/               # Filtros HTTP
│   ├── LazyJwtFilter.java
│   └── RateLimitManager.java
├── aspect/               # Aspectos AOP
│   ├── LazySecurityAspect.java
│   └── RateLimitAspect.java
├── facade/               # Facades estáticas
│   ├── Auth.java         # Acesso ao usuário autenticado
│   └── Guard.java        # Verificações imperativas de autorização
├── exception/            # Exceções e handlers
│   ├── LazySecurityException.java
│   ├── UnauthorizedException.java
│   ├── AccessDeniedException.java
│   ├── RateLimitExceededException.java
│   ├── LazySecurityExceptionHandler.java
│   └── LazySecurityControllerAdvice.java
├── config/               # Auto-configuração
│   └── LazySecurityAutoConfiguration.java
├── resolver/             # Argument resolvers
│   └── LazyUserArgumentResolver.java
├── util/                 # Utilitários
│   ├── LazyAuth.java
│   └── PasswordUtils.java
└── demo/                 # Aplicação de demonstração
    ├── DemoApplication.java
    ├── controller/
    │   ├── AuthController.java
    │   ├── ProfileController.java
    │   ├── AdminController.java
    │   ├── OrderController.java
    │   └── SimpleAuthController.java
    ├── service/
    │   └── UserService.java
    ├── model/
    │   ├── User.java
    │   └── Order.java
    └── dto/
        ├── LoginRequest.java
        ├── RegisterRequest.java
        ├── CreateOrderRequest.java
        └── UpdateProfileRequest.java
```

---

## Dependências

```xml
<!-- Spring Boot Starters -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-aop</artifactId>
</dependency>

<!-- JWT -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.6</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.6</version>
    <scope>runtime</scope>
</dependency>
```

---

## Autor

Desenvolvido por **Abner Lourenço _also known as_ Jed**.

Versão: 1.0.0-SNAPSHOT  
Java: 21+  
Spring Boot: 3.4+

---

## Changelog

### v1.1.0-SNAPSHOT (Atual)

**Breaking Changes:**
- Annotation unificada `@Secured` para toda lógica de autorização

**Novas Funcionalidades:**
- `@Secured` - annotation unificada para toda lógica de autorização:
  - `@Secured` = qualquer usuário autenticado
  - `@Secured("ADMIN")` = requer role ADMIN
  - `@Secured({"A", "B"})` = requer qualquer uma das roles (OR logic)
  - `@Secured(value = {"A", "B"}, all = true)` = requer todas as roles (AND logic)
  - `@Secured(permissions = "x:write")` = requer permissão específica
  - `@Secured(condition = "#id == principal.id")` = expressão SpEL
```

### v1.0.0-SNAPSHOT

**Funcionalidades:**
- Anotações declarativas: `@Secured`, `@Owner`, `@Public`
- Anotações de autenticação: `@Login`, `@Register`, `@RefreshToken`
- JWT com access + refresh tokens (HS384)
- Facades: `Auth` e `Guard` para acesso imperativo
- `LazyUser` injetável em controllers
- Rate limiting via `@RateLimit`
- Auto-configuração via `@EnableLazySecurity`
- Demo application com 73 testes

**Bug Fixes:**
- `JwtService.refresh()` corrigido para usar `jwtProvider.refreshToken()` em vez de `validateToken()` (que rejeitava refresh tokens)
