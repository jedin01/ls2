package ao.sudojed.lss.util;

import java.util.function.Supplier;

import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;

/**
 * Utilitários de segurança do LazySpringSecurity.
 * Métodos convenientes para verificações de segurança em código.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * // Verificar autenticação
 * if (LazyAuth.isAuthenticated()) {
 *     // usuário logado
 * }
 * 
 * // Verificar roles
 * if (LazyAuth.hasRole("ADMIN")) {
 *     // é admin
 * }
 * 
 * // Executar código condicionalmente
 * LazyAuth.ifRole("ADMIN", () -> {
 *     // só executa se for admin
 * });
 * 
 * // Obter usuário atual
 * LazyUser user = LazyAuth.user();
 * }</pre>
 *
 * @author Sudojed Team
 */
public final class LazyAuth {

    private LazyAuth() {
        // Utility class
    }

    /**
     * Obtém o usuário atual.
     */
    public static LazyUser user() {
        return LazySecurityContext.getCurrentUser();
    }

    /**
     * Obtém o ID do usuário atual.
     */
    public static String userId() {
        return LazySecurityContext.getUserId();
    }

    /**
     * Obtém o username do usuário atual.
     */
    public static String username() {
        return LazySecurityContext.getUsername();
    }

    /**
     * Verifica se está autenticado.
     */
    public static boolean isAuthenticated() {
        return LazySecurityContext.isAuthenticated();
    }

    /**
     * Verifica se é anônimo.
     */
    public static boolean isAnonymous() {
        return !isAuthenticated();
    }

    /**
     * Verifica se tem role.
     */
    public static boolean hasRole(String role) {
        return LazySecurityContext.hasRole(role);
    }

    /**
     * Verifica se tem qualquer uma das roles.
     */
    public static boolean hasAnyRole(String... roles) {
        return LazySecurityContext.hasAnyRole(roles);
    }

    /**
     * Verifica se tem todas as roles.
     */
    public static boolean hasAllRoles(String... roles) {
        return LazySecurityContext.hasAllRoles(roles);
    }

    /**
     * Verifica se tem permissão.
     */
    public static boolean hasPermission(String permission) {
        return LazySecurityContext.hasPermission(permission);
    }

    /**
     * Verifica se é admin.
     */
    public static boolean isAdmin() {
        return LazySecurityContext.isAdmin();
    }

    /**
     * Executa ação se autenticado.
     */
    public static void ifAuthenticated(Runnable action) {
        if (isAuthenticated()) {
            action.run();
        }
    }

    /**
     * Executa ação se tem role.
     */
    public static void ifRole(String role, Runnable action) {
        if (hasRole(role)) {
            action.run();
        }
    }

    /**
     * Executa ação se admin.
     */
    public static void ifAdmin(Runnable action) {
        if (isAdmin()) {
            action.run();
        }
    }

    /**
     * Retorna valor se autenticado, senão valor padrão.
     */
    public static <T> T ifAuthenticated(Supplier<T> supplier, T defaultValue) {
        return isAuthenticated() ? supplier.get() : defaultValue;
    }

    /**
     * Retorna valor se tem role, senão valor padrão.
     */
    public static <T> T ifRole(String role, Supplier<T> supplier, T defaultValue) {
        return hasRole(role) ? supplier.get() : defaultValue;
    }

    /**
     * Verifica se o usuário atual é o dono do recurso.
     */
    public static boolean isOwner(String resourceOwnerId) {
        return userId().equals(resourceOwnerId);
    }

    /**
     * Verifica se é admin ou dono do recurso.
     */
    public static boolean isAdminOrOwner(String resourceOwnerId) {
        return isAdmin() || isOwner(resourceOwnerId);
    }
}
