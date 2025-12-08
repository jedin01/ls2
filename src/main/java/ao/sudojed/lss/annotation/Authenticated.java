package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requer autenticação básica (qualquer usuário autenticado).
 * Atalho conveniente para {@code @LazySecured()}.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * @Authenticated
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@LazySecured
public @interface Authenticated {
}
