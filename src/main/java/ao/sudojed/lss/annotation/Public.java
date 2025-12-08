package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marca um endpoint ou método como PÚBLICO (sem autenticação).
 * 
 * <h2>Uso em Métodos</h2>
 * <pre>{@code
 * @Public
 * @PostMapping("/login")
 * public Token login(@RequestBody LoginRequest request) {
 *     return authService.login(request);
 * }
 * 
 * @Public
 * @GetMapping("/health")
 * public Health healthCheck() {
 *     return Health.up();
 * }
 * }</pre>
 * 
 * <h2>Uso em Classes</h2>
 * <pre>{@code
 * @Public
 * @RestController
 * @RequestMapping("/api/public")
 * public class PublicController {
 *     // Todos os endpoints são públicos
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Public {
    
    /**
     * Descrição opcional para documentação.
     */
    String description() default "";
}
