package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Admin;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.facade.Guard;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller administrativo demonstrando uso das facades Auth e Guard.
 * 
 * Duas formas de proteger endpoints:
 * 1. Declarativa: @Admin, @LazySecured (verificacao automatica via AOP)
 * 2. Imperativa: Guard.admin(), Guard.role() (verificacao manual no codigo)
 * 
 * Comparacao com Laravel:
 * - @Admin           -> middleware('admin')
 * - Guard.admin()    -> Gate::authorize('admin')
 * - Auth.user()      -> auth()->user()
 * - Auth.id()        -> auth()->id()
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Lista todos os usuarios do sistema.
     * 
     * Usa @Admin para verificacao declarativa.
     * Usa Auth.username() para obter dados do admin logado.
     */
    @Admin
    @GetMapping("/users")
    public Map<String, Object> listUsers() {
        // Sem parametro LazyUser - usa Auth facade!
        List<Map<String, Object>> users = userService.findAll().stream()
            .map(user -> Map.<String, Object>of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "roles", user.getRoles(),
                "createdAt", user.getCreatedAt().toString()
            ))
            .toList();

        return Map.of(
            "total", users.size(),
            "users", users,
            "requestedBy", Auth.username()  // Auth facade!
        );
    }

    /**
     * Obtem detalhes de um usuario especifico.
     * 
     * Usa Guard.admin() para verificacao imperativa (estilo Laravel Gate).
     * Isso permite logica condicional antes da verificacao.
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<Map<String, Object>> getUser(@PathVariable String userId) {
        // Verificacao imperativa - como Gate::authorize('admin') no Laravel
        Guard.admin();
        
        return userService.findById(userId)
            .map(user -> ResponseEntity.ok(Map.<String, Object>of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "displayName", user.getDisplayName(),
                "roles", user.getRoles(),
                "createdAt", user.getCreatedAt().toString()
            )))
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Deleta um usuario.
     * 
     * Demonstra uso combinado de Guard e Auth:
     * - Guard.admin() para autorizar
     * - Auth.id() para verificar auto-delecao
     */
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Map<String, Object>> deleteUser(@PathVariable String userId) {
        // Verificacao imperativa
        Guard.admin();
        
        // Nao permite auto-delecao - usa Auth.id()!
        if (userId.equals(Auth.id())) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "CANNOT_DELETE_SELF",
                "message", "Voce nao pode deletar sua propria conta"
            ));
        }

        boolean deleted = userService.deleteById(userId);
        
        if (deleted) {
            return ResponseEntity.ok(Map.of(
                "message", "Usuario deletado com sucesso",
                "deletedUserId", userId,
                "deletedBy", Auth.username()  // Auth facade!
            ));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Adiciona role a um usuario.
     * 
     * Usa Guard.role() para exigir role especifica.
     */
    @PostMapping("/users/{userId}/roles")
    public ResponseEntity<Map<String, Object>> addRole(
            @PathVariable String userId,
            @RequestBody Map<String, String> body) {
        
        // Exige role ADMIN - como Gate::authorize('manage-roles') no Laravel
        Guard.role("ADMIN");
        
        String role = body.get("role");
        if (role == null || role.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "MISSING_ROLE",
                "message", "Campo 'role' eh obrigatorio"
            ));
        }

        return userService.findById(userId)
            .map(user -> {
                user.addRole(role);
                userService.save(user);
                return ResponseEntity.ok(Map.<String, Object>of(
                    "message", "Role adicionada com sucesso",
                    "userId", userId,
                    "roles", user.getRoles()
                ));
            })
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Dashboard administrativo com estatisticas.
     * 
     * Demonstra verificacao fluente com Guard.check()
     */
    @GetMapping("/dashboard")
    public Map<String, Object> dashboard() {
        // Verificacao fluente - permite combinar condicoes
        Guard.check()
            .role("ADMIN")
            .authorize();
        
        List<User> allUsers = userService.findAll();
        
        long totalUsers = allUsers.size();
        long adminCount = allUsers.stream()
            .filter(u -> u.getRoles().contains("ADMIN"))
            .count();
        
        return Map.of(
            "stats", Map.of(
                "totalUsers", totalUsers,
                "adminUsers", adminCount,
                "regularUsers", totalUsers - adminCount
            ),
            "admin", Map.of(
                "username", Auth.username(),
                "roles", Auth.user().getRoles(),
                "isAdmin", Auth.isAdmin()
            ),
            "message", "Bem-vindo ao painel administrativo!"
        );
    }

    /**
     * Endpoint que aceita ADMIN ou MANAGER.
     * 
     * Demonstra Guard.anyRole() para multiplas roles aceitas.
     */
    @GetMapping("/reports")
    public Map<String, Object> reports() {
        // Aceita ADMIN ou MANAGER - como middleware('role:admin,manager') no Laravel
        Guard.anyRole("ADMIN", "MANAGER");
        
        return Map.of(
            "reports", List.of(
                Map.of("name", "Vendas Mensais", "value", 15000),
                Map.of("name", "Novos Usuarios", "value", 42),
                Map.of("name", "Pedidos Pendentes", "value", 7)
            ),
            "generatedBy", Auth.username(),
            "userRoles", Auth.user().getRoles()
        );
    }
}
