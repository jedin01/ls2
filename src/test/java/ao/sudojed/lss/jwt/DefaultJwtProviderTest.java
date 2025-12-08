package ao.sudojed.lss.jwt;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.LazySecurityException;

/**
 * Testes para DefaultJwtProvider.
 */
class DefaultJwtProviderTest {

    private DefaultJwtProvider jwtProvider;
    private LazySecurityProperties properties;

    @BeforeEach
    void setUp() {
        properties = new LazySecurityProperties();
        properties.getJwt().setSecret("my-super-secret-key-that-is-at-least-32-characters-long");
        properties.getJwt().setExpiration(3600000L);
        properties.getJwt().setRefreshExpiration(604800000L);
        properties.getJwt().setIssuer("test-issuer");
        
        jwtProvider = new DefaultJwtProvider(properties);
    }

    @Test
    @DisplayName("Deve gerar token válido para usuário")
    void shouldGenerateValidToken() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .roles("USER", "VERIFIED")
                .permissions("posts:read", "posts:write")
                .build();

        // When
        String token = jwtProvider.generateToken(user);

        // Then
        assertNotNull(token);
        assertTrue(jwtProvider.isTokenValid(token));
        assertFalse(jwtProvider.isTokenExpired(token));
    }

    @Test
    @DisplayName("Deve extrair usuário do token")
    void shouldExtractUserFromToken() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .roles("USER", "ADMIN")
                .permissions("users:manage")
                .build();

        String token = jwtProvider.generateToken(user);

        // When
        LazyUser extracted = jwtProvider.validateToken(token);

        // Then
        assertEquals(user.getId(), extracted.getId());
        assertEquals(user.getUsername(), extracted.getUsername());
        assertTrue(extracted.hasRole("USER"));
        assertTrue(extracted.hasRole("ADMIN"));
        assertTrue(extracted.hasPermission("users:manage"));
        assertTrue(extracted.isAuthenticated());
    }

    @Test
    @DisplayName("Deve gerar refresh token")
    void shouldGenerateRefreshToken() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .build();

        // When
        String refreshToken = jwtProvider.generateRefreshToken(user);

        // Then
        assertNotNull(refreshToken);
        assertTrue(jwtProvider.isTokenValid(refreshToken));
    }

    @Test
    @DisplayName("Deve rejeitar token inválido")
    void shouldRejectInvalidToken() {
        // Given
        String invalidToken = "invalid.token.here";

        // When/Then
        assertFalse(jwtProvider.isTokenValid(invalidToken));
        assertThrows(LazySecurityException.class, () -> jwtProvider.validateToken(invalidToken));
    }

    @Test
    @DisplayName("Deve extrair subject do token")
    void shouldExtractSubject() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .build();

        String token = jwtProvider.generateToken(user);

        // When
        String subject = jwtProvider.extractSubject(token);

        // Then
        assertEquals("user-123", subject);
    }

    @Test
    @DisplayName("Deve incluir claims extras no token")
    void shouldIncludeExtraClaims() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .build();

        Map<String, Object> extraClaims = Map.of(
                "email", "john@example.com",
                "organizationId", "org-456"
        );

        // When
        String token = jwtProvider.generateToken(user, extraClaims);
        Map<String, Object> claims = jwtProvider.extractAllClaims(token);

        // Then
        assertEquals("john@example.com", claims.get("email"));
        assertEquals("org-456", claims.get("organizationId"));
    }

    @Test
    @DisplayName("Não deve aceitar refresh token como access token")
    void shouldNotAcceptRefreshTokenAsAccessToken() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .build();

        String refreshToken = jwtProvider.generateRefreshToken(user);

        // When/Then
        assertThrows(LazySecurityException.class, () -> jwtProvider.validateToken(refreshToken));
    }

    @Test
    @DisplayName("Deve falhar com secret vazio")
    void shouldFailWithEmptySecret() {
        // Given
        LazySecurityProperties emptySecretProps = new LazySecurityProperties();
        emptySecretProps.getJwt().setSecret("");

        // When/Then
        assertThrows(LazySecurityException.class, () -> new DefaultJwtProvider(emptySecretProps));
    }
}
