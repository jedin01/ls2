package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Public;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.dto.LoginRequest;
import ao.sudojed.lss.demo.dto.RegisterRequest;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.jwt.TokenPair;
import ao.sudojed.lss.util.PasswordUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller de autenticação - todos os endpoints são públicos.
 * 
 * Demonstra o uso de @Public para endpoints que não requerem autenticação.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    /**
     * Health check - verifica se a API está funcionando.
     * 
     * Uso: GET /auth/health
     */
    @Public
    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
            "status", "UP",
            "service", "LSS Demo API",
            "version", "1.0.0",
            "message", "🚀 LazySpringSecurity está funcionando!"
        );
    }

    /**
     * Registra um novo usuário.
     * 
     * Uso: POST /auth/register
     * Body: { "username": "john", "email": "john@example.com", "password": "123456" }
     */
    @Public
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        // Verifica se usuário já existe
        if (userService.findByUsername(request.username()).isPresent()) {
            return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(Map.of(
                    "error", "USER_EXISTS",
                    "message", "Usuário já existe: " + request.username()
                ));
        }

        // Cria o usuário
        User user = userService.createUser(
            request.username(),
            request.email(),
            request.password()
        );

        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(Map.of(
                "message", "Usuário criado com sucesso!",
                "userId", user.getId(),
                "username", user.getUsername()
            ));
    }

    /**
     * Login - autentica e retorna tokens JWT.
     * 
     * Uso: POST /auth/login
     * Body: { "username": "john", "password": "123456" }
     * 
     * Retorna:
     * {
     *   "access_token": "eyJ...",
     *   "refresh_token": "eyJ...",
     *   "token_type": "Bearer",
     *   "expires_in": 3600
     * }
     */
    @Public
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        // Busca usuário
        User user = userService.findByUsername(request.username())
            .orElse(null);

        // Valida credenciais
        if (user == null || !PasswordUtils.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                    "error", "INVALID_CREDENTIALS",
                    "message", "Usuário ou senha inválidos"
                ));
        }

        // Cria LazyUser para gerar tokens
        LazyUser lazyUser = LazyUser.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles().toArray(new String[0]))
            .claim("email", user.getEmail())
            .claim("displayName", user.getDisplayName())
            .build();

        // Gera tokens
        TokenPair tokens = jwtService.createTokens(lazyUser);

        System.out.println("✅ Login bem-sucedido: " + user.getUsername());

        return ResponseEntity.ok(tokens.toMap());
    }

    /**
     * Refresh token - gera novo access token usando refresh token.
     * 
     * Uso: POST /auth/refresh
     * Body: { "refresh_token": "eyJ..." }
     */
    @Public
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");
        
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                    "error", "MISSING_TOKEN",
                    "message", "refresh_token é obrigatório"
                ));
        }

        try {
            TokenPair newTokens = jwtService.refresh(refreshToken);
            return ResponseEntity.ok(newTokens.toMap());
        } catch (Exception e) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                    "error", "INVALID_REFRESH_TOKEN",
                    "message", "Refresh token inválido ou expirado"
                ));
        }
    }
}
