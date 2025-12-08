package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Authenticated;
import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller de perfil do usuário.
 * 
 * Demonstra o uso de:
 * - @Authenticated para endpoints que requerem apenas login
 * - @LazySecured para endpoints com requisitos específicos
 * - LazyUser como parâmetro para injeção automática do usuário
 */
@RestController
@RequestMapping("/api")
public class ProfileController {

    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Retorna o perfil do usuário logado.
     * 
     * @Authenticated - Qualquer usuário autenticado pode acessar
     * 
     * Note como LazyUser é injetado automaticamente como parâmetro!
     * 
     * Uso: GET /api/profile
     * Header: Authorization: Bearer <token>
     */
    @Authenticated
    @GetMapping("/profile")
    public Map<String, Object> getProfile(LazyUser user) {
        // LazyUser contém os dados do token JWT
        return Map.of(
            "id", user.getId(),
            "username", user.getUsername(),
            "email", user.getClaim("email", ""),
            "roles", user.getRoles(),
            "isAdmin", user.isAdmin(),
            "claims", user.getClaims()
        );
    }

    /**
     * Atualiza o perfil do usuário.
     * 
     * @LazySecured - Requer autenticação (equivalente a @Authenticated)
     * 
     * Uso: PUT /api/profile
     * Header: Authorization: Bearer <token>
     * Body: { "displayName": "John Doe", "email": "newemail@example.com" }
     */
    @LazySecured
    @PutMapping("/profile")
    public ResponseEntity<Map<String, Object>> updateProfile(
            LazyUser user,
            @RequestBody Map<String, String> updates) {
        
        User dbUser = userService.findById(user.getId())
            .orElse(null);
        
        if (dbUser == null) {
            return ResponseEntity.notFound().build();
        }

        // Atualiza campos
        if (updates.containsKey("displayName")) {
            dbUser.setDisplayName(updates.get("displayName"));
        }
        if (updates.containsKey("email")) {
            dbUser.setEmail(updates.get("email"));
        }

        userService.save(dbUser);

        return ResponseEntity.ok(Map.of(
            "message", "Perfil atualizado com sucesso!",
            "user", Map.of(
                "id", dbUser.getId(),
                "username", dbUser.getUsername(),
                "displayName", dbUser.getDisplayName(),
                "email", dbUser.getEmail()
            )
        ));
    }

    /**
     * Retorna informações do usuário atual.
     * 
     * Uso: GET /api/me
     */
    @LazySecured
    @GetMapping("/me")
    public Map<String, Object> me(LazyUser user) {
        return Map.of(
            "userId", user.getId(),
            "username", user.getUsername(),
            "roles", user.getRoles(),
            "permissions", user.getPermissions(),
            "authenticated", user.isAuthenticated(),
            "admin", user.isAdmin()
        );
    }
}
