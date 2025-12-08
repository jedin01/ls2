package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Protege um endpoint/método requerendo autenticação e roles específicas.
 * 
 * <h2>Autenticação Simples (qualquer usuário autenticado)</h2>
 * <pre>{@code
 * @LazySecured
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 * 
 * <h2>Roles Específicas</h2>
 * <pre>{@code
 * @LazySecured(roles = "ADMIN")
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 * 
 * @LazySecured(roles = {"ADMIN", "MANAGER"})
 * @GetMapping("/reports")
 * public List<Report> getReports() { }
 * }</pre>
 * 
 * <h2>Lógica de Roles</h2>
 * <pre>{@code
 * // Qualquer uma das roles (OR)
 * @LazySecured(roles = {"ADMIN", "MANAGER"}, logic = RoleLogic.ANY)
 * 
 * // Todas as roles necessárias (AND)
 * @LazySecured(roles = {"VERIFIED", "PREMIUM"}, logic = RoleLogic.ALL)
 * }</pre>
 * 
 * <h2>Combinado com Permissões</h2>
 * <pre>{@code
 * @LazySecured(
 *     roles = "USER",
 *     permissions = "users:read"
 * )
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface LazySecured {

    /**
     * Roles permitidas para acessar o recurso.
     * Se vazio, apenas autenticação é necessária.
     */
    String[] roles() default {};

    /**
     * Permissões específicas requeridas (fine-grained).
     * Ex: "users:read", "posts:write"
     */
    String[] permissions() default {};

    /**
     * Lógica para múltiplas roles.
     */
    RoleLogic logic() default RoleLogic.ANY;

    /**
     * Mensagem customizada de erro quando acesso negado.
     */
    String message() default "Access denied";

    /**
     * SpEL expression para validação dinâmica.
     * Ex: "#userId == authentication.principal.id"
     */
    String condition() default "";
    
    /**
     * Lógica de avaliação de roles.
     */
    enum RoleLogic {
        /** Qualquer uma das roles é suficiente (OR) */
        ANY,
        /** Todas as roles são necessárias (AND) */
        ALL
    }
}
