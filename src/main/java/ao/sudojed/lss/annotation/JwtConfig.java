package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Configuração JWT para LazySpringSecurity.
 * 
 * <h2>Exemplo</h2>
 * <pre>{@code
 * @JwtConfig(
 *     secret = "${JWT_SECRET}",
 *     expiration = 3600000,  // 1 hora
 *     refreshExpiration = 604800000  // 7 dias
 * )
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface JwtConfig {

    /**
     * Secret key para assinar tokens JWT.
     * Suporta placeholders do Spring: ${JWT_SECRET}
     * 
     * IMPORTANTE: Use no mínimo 256 bits (32 caracteres) para HS256.
     */
    String secret() default "";

    /**
     * Tempo de expiração do access token em milissegundos.
     * Padrão: 1 hora (3600000ms)
     */
    long expiration() default 3600000L;

    /**
     * Tempo de expiração do refresh token em milissegundos.
     * Padrão: 7 dias (604800000ms)
     */
    long refreshExpiration() default 604800000L;

    /**
     * Nome do header HTTP para o token.
     * Padrão: "Authorization"
     */
    String header() default "Authorization";

    /**
     * Prefixo do token no header.
     * Padrão: "Bearer "
     */
    String prefix() default "Bearer ";

    /**
     * Issuer do token JWT.
     */
    String issuer() default "lazy-spring-security";

    /**
     * Audience do token JWT.
     */
    String audience() default "";

    /**
     * Algoritmo de assinatura.
     * Padrão: HS256
     */
    String algorithm() default "HS256";
}
