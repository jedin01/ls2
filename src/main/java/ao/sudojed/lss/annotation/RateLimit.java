package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Aplica rate limiting a um endpoint.
 * Protege contra abuso e DDoS.
 * 
 * <h2>Uso Básico</h2>
 * <pre>{@code
 * @RateLimit(requests = 100, window = 60)  // 100 requests por minuto
 * @PostMapping("/api/data")
 * public Data processData() { }
 * }</pre>
 * 
 * <h2>Por Usuário</h2>
 * <pre>{@code
 * @RateLimit(requests = 10, window = 60, perUser = true)
 * @PostMapping("/messages")
 * public Message sendMessage() { }
 * }</pre>
 * 
 * <h2>Endpoints de Login</h2>
 * <pre>{@code
 * @RateLimit(requests = 5, window = 300, key = "ip")  // 5 tentativas por 5 min por IP
 * @PostMapping("/login")
 * public Token login() { }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    /**
     * Número máximo de requests permitidos na janela de tempo.
     */
    int requests();

    /**
     * Janela de tempo em segundos.
     */
    int window();

    /**
     * Chave para rate limiting: "ip", "user", "token", ou SpEL expression.
     * Padrão: "ip"
     */
    String key() default "ip";

    /**
     * Se true, limite é aplicado por usuário autenticado.
     */
    boolean perUser() default false;

    /**
     * Mensagem de erro quando limite excedido.
     */
    String message() default "Rate limit exceeded. Please try again later.";

    /**
     * Código HTTP quando limite excedido.
     * Padrão: 429 Too Many Requests
     */
    int statusCode() default 429;
}
