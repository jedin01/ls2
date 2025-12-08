package ao.sudojed.lss.integration;

import ao.sudojed.lss.annotation.*;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.jwt.TokenPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * Controller de teste para demonstrar funcionalidades do LSS.
 */
@RestController
@RequestMapping("/api")
public class TestController {

    @Autowired
    private JwtService jwtService;

    // ========== Endpoints Públicos ==========

    @Public
    @GetMapping("/public/health")
    public Map<String, String> health() {
        return Map.of("status", "UP", "service", "LSS Test");
    }

    @Public
    @PostMapping("/public/login")
    public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
        // Simula validação de credenciais
        String username = credentials.get("username");

        LazyUser user = LazyUser.builder()
                .id("user-" + UUID.randomUUID().toString().substring(0, 8))
                .username(username)
                .roles("USER")
                .build();

        TokenPair tokens = jwtService.createTokens(user);
        return tokens.toMap();
    }

    // ========== Endpoints Protegidos ==========

    @LazySecured
    @GetMapping("/profile")
    public Map<String, Object> profile(LazyUser user) {
        return Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "roles", user.getRoles()
        );
    }

    @LazySecured
    @GetMapping("/me")
    public Map<String, Object> me(LazyUser user) {
        return Map.of(
                "userId", user.getId(),
                "username", user.getUsername(),
                "roles", user.getRoles(),
                "isAdmin", user.isAdmin(),
                "isAuthenticated", user.isAuthenticated()
        );
    }

    @LazySecured(roles = {"USER", "MANAGER"})
    @GetMapping("/dashboard")
    public Map<String, String> dashboard() {
        return Map.of("message", "Welcome to dashboard");
    }

    // ========== Endpoints Admin ==========

    @Admin
    @GetMapping("/admin/users")
    public List<Map<String, String>> listUsers() {
        return List.of(
                Map.of("id", "1", "name", "John"),
                Map.of("id", "2", "name", "Jane"),
                Map.of("id", "3", "name", "Admin")
        );
    }

    // ========== Endpoints com @Owner ==========

    @LazySecured
    @Owner(field = "userId", adminBypass = true)
    @GetMapping("/users/{userId}/orders")
    public List<Map<String, Object>> getUserOrders(@PathVariable String userId) {
        return List.of(
                Map.of("orderId", "ORD-001", "userId", userId, "total", 99.99),
                Map.of("orderId", "ORD-002", "userId", userId, "total", 149.99)
        );
    }
}
