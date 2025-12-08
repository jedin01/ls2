package ao.sudojed.lss.jwt;

import java.util.Map;

import ao.sudojed.lss.core.LazyUser;

/**
 * Interface para geração e validação de tokens JWT.
 * Implemente esta interface para customizar a lógica de tokens.
 * 
 * <h2>Implementação Padrão</h2>
 * O LSS fornece {@link DefaultJwtProvider} que funciona out-of-the-box.
 * 
 * <h2>Implementação Customizada</h2>
 * <pre>{@code
 * @Component
 * public class MyJwtProvider implements JwtProvider {
 *     @Override
 *     public String generateToken(LazyUser user) {
 *         // Sua lógica customizada
 *     }
 *     // ...
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public interface JwtProvider {

    /**
     * Gera um access token para o usuário.
     */
    String generateToken(LazyUser user);

    /**
     * Gera um access token com claims adicionais.
     */
    String generateToken(LazyUser user, Map<String, Object> extraClaims);

    /**
     * Gera um refresh token para o usuário.
     */
    String generateRefreshToken(LazyUser user);

    /**
     * Valida um token e retorna o usuário.
     * 
     * @throws ao.sudojed.lss.exception.LazySecurityException se token inválido
     */
    LazyUser validateToken(String token);

    /**
     * Verifica se um token é válido (não expirado, assinatura correta).
     */
    boolean isTokenValid(String token);

    /**
     * Verifica se um token está expirado.
     */
    boolean isTokenExpired(String token);

    /**
     * Extrai o subject (geralmente userId ou username) do token.
     */
    String extractSubject(String token);

    /**
     * Extrai um claim específico do token.
     */
    <T> T extractClaim(String token, String claimName, Class<T> type);

    /**
     * Extrai todos os claims do token.
     */
    Map<String, Object> extractAllClaims(String token);

    /**
     * Renova um token (gera novo access token a partir de refresh token).
     */
    String refreshToken(String refreshToken);
}
