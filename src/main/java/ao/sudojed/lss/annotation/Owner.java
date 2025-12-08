package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Valida que o usuário atual é o dono do recurso.
 * Útil para endpoints onde o usuário só pode acessar seus próprios dados.
 * 
 * <h2>Uso Básico</h2>
 * <pre>{@code
 * @Owner(field = "userId")
 * @GetMapping("/users/{userId}/orders")
 * public List<Order> getUserOrders(@PathVariable Long userId) { }
 * }</pre>
 * 
 * <h2>Com Bypass para Admin</h2>
 * <pre>{@code
 * @Owner(field = "id", adminBypass = true)
 * @PutMapping("/users/{id}")
 * public User updateUser(@PathVariable Long id, @RequestBody User user) {
 *     // Usuário pode editar apenas seu próprio perfil
 *     // Admin pode editar qualquer perfil
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Owner {

    /**
     * Nome do parâmetro/campo que contém o ID do dono.
     * Pode ser path variable, request param, ou campo do body.
     */
    String field();

    /**
     * Campo do principal que contém o ID do usuário.
     * Padrão: "id"
     */
    String principalField() default "id";

    /**
     * Roles que podem bypassar a verificação de ownership.
     */
    String[] bypassRoles() default {"ADMIN"};

    /**
     * Permite que ADMIN bypasse a verificação.
     */
    boolean adminBypass() default true;

    /**
     * Mensagem de erro quando não é o dono.
     */
    String message() default "You can only access your own resources";
}
