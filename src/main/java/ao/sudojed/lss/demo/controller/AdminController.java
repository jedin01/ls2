package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Admin;
import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller administrativo.
 * 
 * Demonstra o uso de:
 * - @Admin para endpoints exclusivos de administradores
 * - @LazySecured(roles = {...}) para controle granular de roles
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Lista todos os usuários do sistema.
     * 
     * @Admin - Apenas usuários com role ADMIN podem acessar
     * 
     * Uso: GET /api/admin/users
     * Header: Authorization: Bearer <admin_token>
     */
    @Admin
    @GetMapping("/users")
    public Map<String, Object> listUsers(LazyUser admin) {
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
            "requestedBy", admin.getUsername()
        );
    }

    /**
     * Obtém detalhes de um usuário específico.
     * 
     * @Admin - Apenas administradores
     * 
     * Uso: GET /api/admin/users/{userId}
     */
    @Admin
    @GetMapping("/users/{userId}")
    public ResponseEntity<Map<String, Object>> getUser(@PathVariable String userId) {
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
     * Deleta um usuário.
     * 
     * @Admin - Apenas administradores podem deletar usuários
     * 
     * Uso: DELETE /api/admin/users/{userId}
     */
    @Admin
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Map<String, Object>> deleteUser(
            @PathVariable String userId,
            LazyUser admin) {
        
        // Não permite auto-deleção
        if (userId.equals(admin.getId())) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "CANNOT_DELETE_SELF",
                "message", "Você não pode deletar sua própria conta"
            ));
        }

        boolean deleted = userService.deleteById(userId);
        
        if (deleted) {
            return ResponseEntity.ok(Map.of(
                "message", "Usuário deletado com sucesso",
                "deletedUserId", userId,
                "deletedBy", admin.getUsername()
            ));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Adiciona role a um usuário.
     * 
     * Exemplo de @LazySecured com roles específicas
     * 
     * Uso: POST /api/admin/users/{userId}/roles
     * Body: { "role": "MANAGER" }
     */
    @LazySecured(roles = "ADMIN", message = "Apenas administradores podem modificar roles")
    @PostMapping("/users/{userId}/roles")
    public ResponseEntity<Map<String, Object>> addRole(
            @PathVariable String userId,
            @RequestBody Map<String, String> body) {
        
        String role = body.get("role");
        if (role == null || role.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "MISSING_ROLE",
                "message", "Campo 'role' é obrigatório"
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
     * Dashboard administrativo com estatísticas.
     * 
     * Uso: GET /api/admin/dashboard
     */
    @Admin
    @GetMapping("/dashboard")
    public Map<String, Object> dashboard(LazyUser admin) {
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
                "username", admin.getUsername(),
                "roles", admin.getRoles()
            ),
            "message", "Bem-vindo ao painel administrativo!"
        );
    }
}
