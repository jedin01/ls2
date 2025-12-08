package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import ao.sudojed.lss.config.LazySecurityAutoConfiguration;

/**
 * Habilita o LazySpringSecurity na aplicação Spring Boot.
 * 
 * <h2>Uso Básico</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(secret = "${app.jwt.secret}"),
 *     publicPaths = {"/api/public/**", "/health", "/swagger-ui/**"}
 * )
 * @SpringBootApplication
 * public class MyApplication { }
 * }</pre>
 * 
 * <h2>Configuração Completa</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(
 *         secret = "${JWT_SECRET}",
 *         expiration = 86400000,
 *         header = "Authorization",
 *         prefix = "Bearer "
 *     ),
 *     publicPaths = {"/api/auth/**", "/actuator/health"},
 *     defaultRole = "USER",
 *     csrfEnabled = false,
 *     corsEnabled = true
 * )
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(LazySecurityAutoConfiguration.class)
public @interface EnableLazySecurity {

    /**
     * Configuração JWT. Obrigatório para autenticação stateless.
     */
    JwtConfig jwt() default @JwtConfig;

    /**
     * Paths públicos que não requerem autenticação.
     * Suporta Ant patterns: /api/**, /public/*, etc.
     */
    String[] publicPaths() default {};

    /**
     * Role padrão para usuários autenticados sem role específica.
     */
    String defaultRole() default "USER";

    /**
     * Habilita/desabilita CSRF protection.
     * Padrão: false (APIs REST geralmente não precisam)
     */
    boolean csrfEnabled() default false;

    /**
     * Habilita/desabilita CORS.
     */
    boolean corsEnabled() default true;

    /**
     * Origins permitidas para CORS.
     */
    String[] corsOrigins() default {"*"};

    /**
     * Métodos HTTP permitidos para CORS.
     */
    String[] corsMethods() default {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"};

    /**
     * Headers permitidos para CORS.
     */
    String[] corsHeaders() default {"*"};

    /**
     * Paths que requerem HTTPS.
     */
    String[] securePaths() default {};

    /**
     * Habilita logs de debug para troubleshooting.
     */
    boolean debug() default false;
}
