package ao.sudojed.lss.util;

import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;

/**
 * Testes para LazyAuth.
 */
class LazyAuthTest {

    @BeforeEach
    void setUp() {
        LazySecurityContext.clear();
    }

    @AfterEach
    void tearDown() {
        LazySecurityContext.clear();
    }

    @Test
    @DisplayName("Deve retornar usuário anônimo quando não autenticado")
    void shouldReturnAnonymousWhenNotAuthenticated() {
        // When
        LazyUser user = LazyAuth.user();

        // Then
        assertNotNull(user);
        assertFalse(user.isAuthenticated());
        assertEquals("anonymous", user.getId());
    }

    @Test
    @DisplayName("Deve verificar autenticação corretamente")
    void shouldCheckAuthentication() {
        // Given - sem usuário
        assertFalse(LazyAuth.isAuthenticated());
        assertTrue(LazyAuth.isAnonymous());

        // Given - com usuário
        LazyUser user = LazyUser.builder()
                .id("123")
                .username("test")
                .authenticated(true)
                .build();
        LazySecurityContext.setCurrentUser(user);

        // Then
        assertTrue(LazyAuth.isAuthenticated());
        assertFalse(LazyAuth.isAnonymous());
    }

    @Test
    @DisplayName("Deve verificar roles")
    void shouldCheckRoles() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("123")
                .username("test")
                .roles("USER", "VERIFIED")
                .build();
        LazySecurityContext.setCurrentUser(user);

        // Then
        assertTrue(LazyAuth.hasRole("USER"));
        assertTrue(LazyAuth.hasRole("VERIFIED"));
        assertFalse(LazyAuth.hasRole("ADMIN"));
        
        assertTrue(LazyAuth.hasAnyRole("USER", "ADMIN"));
        assertFalse(LazyAuth.hasAnyRole("ADMIN", "SUPER"));
        
        assertTrue(LazyAuth.hasAllRoles("USER", "VERIFIED"));
        assertFalse(LazyAuth.hasAllRoles("USER", "ADMIN"));
    }

    @Test
    @DisplayName("Deve verificar admin")
    void shouldCheckAdmin() {
        // Given - user normal
        LazyUser user = LazyUser.builder()
                .id("123")
                .username("test")
                .roles("USER")
                .build();
        LazySecurityContext.setCurrentUser(user);
        assertFalse(LazyAuth.isAdmin());

        // Given - admin
        LazyUser admin = LazyUser.builder()
                .id("456")
                .username("admin")
                .roles("ADMIN")
                .build();
        LazySecurityContext.setCurrentUser(admin);
        assertTrue(LazyAuth.isAdmin());
    }

    @Test
    @DisplayName("Deve verificar ownership")
    void shouldCheckOwnership() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("test")
                .roles("USER")
                .build();
        LazySecurityContext.setCurrentUser(user);

        // Then
        assertTrue(LazyAuth.isOwner("user-123"));
        assertFalse(LazyAuth.isOwner("user-456"));
    }

    @Test
    @DisplayName("Deve verificar admin ou owner")
    void shouldCheckAdminOrOwner() {
        // Given - user normal, é owner
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("test")
                .roles("USER")
                .build();
        LazySecurityContext.setCurrentUser(user);

        assertTrue(LazyAuth.isAdminOrOwner("user-123")); // é owner
        assertFalse(LazyAuth.isAdminOrOwner("user-456")); // não é owner nem admin

        // Given - admin, não é owner
        LazyUser admin = LazyUser.builder()
                .id("admin-999")
                .username("admin")
                .roles("ADMIN")
                .build();
        LazySecurityContext.setCurrentUser(admin);

        assertTrue(LazyAuth.isAdminOrOwner("user-123")); // é admin
        assertTrue(LazyAuth.isAdminOrOwner("any-id")); // é admin
    }

    @Test
    @DisplayName("Deve executar ação condicionalmente")
    void shouldExecuteConditionally() {
        // Given
        LazyUser admin = LazyUser.builder()
                .id("123")
                .username("admin")
                .roles("ADMIN")
                .authenticated(true)
                .build();
        LazySecurityContext.setCurrentUser(admin);

        AtomicBoolean executed = new AtomicBoolean(false);

        // When
        LazyAuth.ifAdmin(() -> executed.set(true));

        // Then
        assertTrue(executed.get());
    }

    @Test
    @DisplayName("Deve retornar valor condicional")
    void shouldReturnConditionalValue() {
        // Given - autenticado
        LazyUser user = LazyUser.builder()
                .id("123")
                .username("test")
                .authenticated(true)
                .build();
        LazySecurityContext.setCurrentUser(user);

        // When
        String result = LazyAuth.ifAuthenticated(() -> "authenticated", "anonymous");

        // Then
        assertEquals("authenticated", result);

        // Given - não autenticado
        LazySecurityContext.clear();
        result = LazyAuth.ifAuthenticated(() -> "authenticated", "anonymous");
        assertEquals("anonymous", result);
    }

    @Test
    @DisplayName("Deve obter userId e username")
    void shouldGetUserIdAndUsername() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .build();
        LazySecurityContext.setCurrentUser(user);

        // Then
        assertEquals("user-123", LazyAuth.userId());
        assertEquals("john.doe", LazyAuth.username());
    }
}
