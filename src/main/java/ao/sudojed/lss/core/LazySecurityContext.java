package ao.sudojed.lss.core;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Contexto de segurança simplificado do LazySpringSecurity.
 * Provê acesso fácil ao usuário atual sem boilerplate.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * // Obtém usuário atual (nunca null)
 * LazyUser user = LazySecurityContext.getCurrentUser();
 * 
 * // Verifica se está autenticado
 * if (LazySecurityContext.isAuthenticated()) {
 *     // ...
 * }
 * 
 * // Obtém ID do usuário diretamente
 * String userId = LazySecurityContext.getUserId();
 * 
 * // Verifica role
 * if (LazySecurityContext.hasRole("ADMIN")) {
 *     // ...
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public final class LazySecurityContext {

    private static final ThreadLocal<LazyUser> userHolder = new ThreadLocal<>();

    private LazySecurityContext() {
        // Utility class
    }

    /**
     * Obtém o usuário atual autenticado.
     * Retorna usuário anônimo se não autenticado.
     */
    public static LazyUser getCurrentUser() {
        LazyUser cachedUser = userHolder.get();
        if (cachedUser != null) {
            return cachedUser;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return LazyUser.anonymous();
        }

        Object principal = authentication.getPrincipal();
        
        if (principal instanceof LazyUser) {
            return (LazyUser) principal;
        }

        // Fallback para outros tipos de principal
        return LazyUser.builder()
                .id(authentication.getName())
                .username(authentication.getName())
                .authenticated(authentication.isAuthenticated())
                .roles(authentication.getAuthorities().stream()
                        .map(a -> a.getAuthority().replace("ROLE_", ""))
                        .toList())
                .build();
    }

    /**
     * Obtém o usuário atual como Optional.
     * Empty se não autenticado.
     */
    public static Optional<LazyUser> getUser() {
        LazyUser user = getCurrentUser();
        return user.isAuthenticated() ? Optional.of(user) : Optional.empty();
    }

    /**
     * Verifica se há um usuário autenticado.
     */
    public static boolean isAuthenticated() {
        return getCurrentUser().isAuthenticated();
    }

    /**
     * Obtém o ID do usuário atual.
     */
    public static String getUserId() {
        return getCurrentUser().getId();
    }

    /**
     * Obtém o username do usuário atual.
     */
    public static String getUsername() {
        return getCurrentUser().getUsername();
    }

    /**
     * Verifica se o usuário tem uma role específica.
     */
    public static boolean hasRole(String role) {
        return getCurrentUser().hasRole(role);
    }

    /**
     * Verifica se o usuário tem qualquer uma das roles.
     */
    public static boolean hasAnyRole(String... roles) {
        return getCurrentUser().hasAnyRole(roles);
    }

    /**
     * Verifica se o usuário tem todas as roles.
     */
    public static boolean hasAllRoles(String... roles) {
        return getCurrentUser().hasAllRoles(roles);
    }

    /**
     * Verifica se o usuário tem uma permissão específica.
     */
    public static boolean hasPermission(String permission) {
        return getCurrentUser().hasPermission(permission);
    }

    /**
     * Verifica se o usuário é admin.
     */
    public static boolean isAdmin() {
        return getCurrentUser().isAdmin();
    }

    /**
     * Define o usuário no contexto (uso interno).
     */
    public static void setCurrentUser(LazyUser user) {
        userHolder.set(user);
    }

    /**
     * Limpa o contexto do usuário (uso interno).
     */
    public static void clear() {
        userHolder.remove();
    }

    /**
     * Executa uma ação como um usuário específico (útil para testes).
     */
    public static <T> T runAs(LazyUser user, java.util.function.Supplier<T> action) {
        LazyUser previous = userHolder.get();
        try {
            setCurrentUser(user);
            return action.get();
        } finally {
            if (previous != null) {
                setCurrentUser(previous);
            } else {
                clear();
            }
        }
    }

    /**
     * Executa uma ação como um usuário específico (sem retorno).
     */
    public static void runAs(LazyUser user, Runnable action) {
        runAs(user, () -> {
            action.run();
            return null;
        });
    }
}
