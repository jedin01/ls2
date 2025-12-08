package ao.sudojed.lss.core;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Testes para LazyUser.
 */
class LazyUserTest {

    @Test
    @DisplayName("Deve criar usuário com builder")
    void shouldCreateUserWithBuilder() {
        // When
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .roles("USER", "ADMIN")
                .permissions("posts:read", "posts:write")
                .claim("email", "john@example.com")
                .authenticated(true)
                .build();

        // Then
        assertEquals("user-123", user.getId());
        assertEquals("john.doe", user.getUsername());
        assertTrue(user.isAuthenticated());
        assertEquals(Set.of("USER", "ADMIN"), user.getRoles());
        assertEquals(Set.of("posts:read", "posts:write"), user.getPermissions());
        assertEquals("john@example.com", user.getClaim("email"));
    }

    @Test
    @DisplayName("Deve verificar role corretamente")
    void shouldCheckRoleCorrectly() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER", "VERIFIED")
                .build();

        // Then
        assertTrue(user.hasRole("USER"));
        assertTrue(user.hasRole("VERIFIED"));
        assertFalse(user.hasRole("ADMIN"));
        
        // Case insensitive
        assertTrue(user.hasRole("user"));
        assertTrue(user.hasRole("User"));
    }

    @Test
    @DisplayName("Deve verificar hasAnyRole corretamente")
    void shouldCheckHasAnyRole() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER")
                .build();

        // Then
        assertTrue(user.hasAnyRole("USER", "ADMIN"));
        assertTrue(user.hasAnyRole("ADMIN", "USER", "MANAGER"));
        assertFalse(user.hasAnyRole("ADMIN", "MANAGER"));
    }

    @Test
    @DisplayName("Deve verificar hasAllRoles corretamente")
    void shouldCheckHasAllRoles() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER", "VERIFIED", "PREMIUM")
                .build();

        // Then
        assertTrue(user.hasAllRoles("USER", "VERIFIED"));
        assertTrue(user.hasAllRoles("USER", "VERIFIED", "PREMIUM"));
        assertFalse(user.hasAllRoles("USER", "ADMIN"));
    }

    @Test
    @DisplayName("Deve verificar permissões")
    void shouldCheckPermissions() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .permissions("posts:read", "posts:write", "users:read")
                .build();

        // Then
        assertTrue(user.hasPermission("posts:read"));
        assertTrue(user.hasPermission("posts:write"));
        assertFalse(user.hasPermission("users:delete"));
    }

    @Test
    @DisplayName("Deve identificar admin")
    void shouldIdentifyAdmin() {
        // Given
        LazyUser admin = LazyUser.builder()
                .id("1")
                .username("admin")
                .roles("ADMIN")
                .build();

        LazyUser user = LazyUser.builder()
                .id("2")
                .username("user")
                .roles("USER")
                .build();

        // Then
        assertTrue(admin.isAdmin());
        assertFalse(user.isAdmin());
    }

    @Test
    @DisplayName("Deve criar usuário anônimo")
    void shouldCreateAnonymousUser() {
        // When
        LazyUser anonymous = LazyUser.anonymous();

        // Then
        assertEquals("anonymous", anonymous.getId());
        assertEquals("anonymous", anonymous.getUsername());
        assertFalse(anonymous.isAuthenticated());
        assertTrue(anonymous.getRoles().isEmpty());
    }

    @Test
    @DisplayName("Deve normalizar roles com prefixo ROLE_")
    void shouldNormalizeRolesWithPrefix() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER")
                .build();

        // Then - deve aceitar com ou sem prefixo
        assertTrue(user.hasRole("USER"));
        assertTrue(user.hasRole("ROLE_USER"));
    }

    @Test
    @DisplayName("Deve retornar claim com valor padrão")
    void shouldReturnClaimWithDefault() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .claim("existing", "value")
                .build();

        // Then
        assertEquals("value", user.getClaim("existing", "default"));
        assertEquals("default", user.getClaim("nonexistent", "default"));
    }

    @Test
    @DisplayName("Deve verificar existência de claim")
    void shouldCheckClaimExistence() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .claim("email", "test@example.com")
                .build();

        // Then
        assertTrue(user.hasClaim("email"));
        assertFalse(user.hasClaim("phone"));
    }

    @Test
    @DisplayName("Deve implementar equals e hashCode baseado em id")
    void shouldImplementEqualsAndHashCode() {
        // Given
        LazyUser user1 = LazyUser.builder().id("123").username("john").build();
        LazyUser user2 = LazyUser.builder().id("123").username("jane").build();
        LazyUser user3 = LazyUser.builder().id("456").username("john").build();

        // Then
        assertEquals(user1, user2); // mesmo id
        assertNotEquals(user1, user3); // id diferente
        assertEquals(user1.hashCode(), user2.hashCode());
    }
}
