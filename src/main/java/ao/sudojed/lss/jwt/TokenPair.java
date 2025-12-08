package ao.sudojed.lss.jwt;

import java.util.Map;

/**
 * Resultado da geração de tokens.
 * Contém access token e refresh token.
 *
 * @author Sudojed Team
 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType
) {
    
    public static TokenPair of(String accessToken, String refreshToken, long expiresIn) {
        return new TokenPair(accessToken, refreshToken, expiresIn, "Bearer");
    }

    /**
     * Converte para Map (útil para retornar em APIs).
     */
    public Map<String, Object> toMap() {
        return Map.of(
                "access_token", accessToken,
                "refresh_token", refreshToken,
                "expires_in", expiresIn,
                "token_type", tokenType
        );
    }
}
