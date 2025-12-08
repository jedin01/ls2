package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requer role de ADMIN para acessar o recurso.
 * Atalho conveniente para {@code @LazySecured(roles = "ADMIN")}.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * @Admin
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 * 
 * @Admin
 * @RestController
 * @RequestMapping("/api/admin")
 * public class AdminController { }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@LazySecured(roles = "ADMIN")
public @interface Admin {
}
