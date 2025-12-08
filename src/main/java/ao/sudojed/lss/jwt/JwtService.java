package ao.sudojed.lss.jwt;

import java.util.Map;

import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.core.LazyUser;

/**
 * Serviço de alto nível para operações com JWT.
 * Abstrai a complexidade do JwtProvider.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * @Autowired
 * private JwtService jwtService;
 * 
 * public TokenPair login(String username, String password) {
 *     // Valida credenciais...
 *     LazyUser user = LazyUser.builder()
 *         .id("123")
 *         .username(username)
 *         .roles("USER")
 *         .build();
 *     
 *     return jwtService.createTokens(user);
 * }
 * 
 * public TokenPair refreshTokens(String refreshToken) {
 *     return jwtService.refresh(refreshToken);
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public class JwtService {

    private final JwtProvider jwtProvider;
    private final LazySecurityProperties.Jwt jwtConfig;

    public JwtService(JwtProvider jwtProvider, LazySecurityProperties properties) {
        this.jwtProvider = jwtProvider;
        this.jwtConfig = properties.getJwt();
    }

    /**
     * Cria par de tokens (access + refresh) para o usuário.
     */
    public TokenPair createTokens(LazyUser user) {
        String accessToken = jwtProvider.generateToken(user);
        String refreshToken = jwtProvider.generateRefreshToken(user);
        return TokenPair.of(accessToken, refreshToken, jwtConfig.getExpiration() / 1000);
    }

    /**
     * Cria par de tokens com claims adicionais.
     */
    public TokenPair createTokens(LazyUser user, Map<String, Object> extraClaims) {
        String accessToken = jwtProvider.generateToken(user, extraClaims);
        String refreshToken = jwtProvider.generateRefreshToken(user);
        return TokenPair.of(accessToken, refreshToken, jwtConfig.getExpiration() / 1000);
    }

    /**
     * Cria apenas access token.
     */
    public String createAccessToken(LazyUser user) {
        return jwtProvider.generateToken(user);
    }

    /**
     * Cria apenas refresh token.
     */
    public String createRefreshToken(LazyUser user) {
        return jwtProvider.generateRefreshToken(user);
    }

    /**
     * Valida token e retorna usuário.
     */
    public LazyUser validate(String token) {
        return jwtProvider.validateToken(token);
    }

    /**
     * Verifica se token é válido.
     */
    public boolean isValid(String token) {
        return jwtProvider.isTokenValid(token);
    }

    /**
     * Renova tokens usando refresh token.
     */
    public TokenPair refresh(String refreshToken) {
        LazyUser user = jwtProvider.validateToken(refreshToken);
        return createTokens(user);
    }

    /**
     * Extrai usuário do token sem validar expiração.
     * Útil para refresh de tokens expirados.
     */
    public String extractUserId(String token) {
        return jwtProvider.extractSubject(token);
    }
}
