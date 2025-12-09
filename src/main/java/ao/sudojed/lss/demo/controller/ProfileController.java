package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Authenticated;
import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import ao.sudojed.lss.facade.Auth;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller de perfil do usuario.
 * 
 * Demonstra duas formas de acesso ao usuario:
 * 
 * 1. Via parametro LazyUser (injecao automatica):
 *    public Map<String, Object> getProfile(LazyUser user) { ... }
 * 
 * 2. Via facade Auth (estilo Laravel):
 *    Auth.user()     // obtem usuario
 *    Auth.id()       // obtem ID
 *    Auth.hasRole()  // verifica role
 */
@RestController
@RequestMapping("/api")
public class ProfileController {

    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Retorna o perfil do usuario logado.
     * 
     * Exemplo usando parametro LazyUser (forma tradicional)
     * 
     * Uso: GET /api/profile
     * Header: Authorization: Bearer <token>
     */
    @Authenticated
    @GetMapping("/profile")
    public Map<String, Object> getProfile(LazyUser user) {
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
     * Retorna informacoes do usuario atual usando facade Auth.
     * 
     * Exemplo usando Auth facade (estilo Laravel):
     * - Auth.user()    equivale a  Auth::user()
     * - Auth.id()      equivale a  Auth::id()
     * - Auth.isAdmin() equivale a  Auth::user()->isAdmin()
     * 
     * Uso: GET /api/me
     * Header: Authorization: Bearer <token>
     */
    @Authenticated
    @GetMapping("/me")
    public Map<String, Object> me() {
        // Usa facade Auth (estilo Laravel) - sem precisar de parametro!
        return Map.of(
            "id", Auth.id(),
            "username", Auth.username(),
            "email", Auth.claim("email"),
            "roles", Auth.user().getRoles(),
            "isAdmin", Auth.isAdmin(),
            "isGuest", Auth.guest()
        );
    }

    /**
     * Atualiza o perfil do usuario.
     * 
     * Uso: PUT /api/profile
     * Body: { "displayName": "John Doe", "email": "newemail@example.com" }
     */
    @LazySecured
    @PutMapping("/profile")
    public ResponseEntity<Map<String, Object>> updateProfile(@RequestBody Map<String, String> updates) {
        // Usa Auth.id() para obter ID do usuario atual
        User dbUser = userService.findById(Auth.id()).orElse(null);
        
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
}
