package ao.sudojed.lss.facade;

import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.UnauthorizedException;
import ao.sudojed.lss.jwt.TokenBlacklist;
import ao.sudojed.lss.util.PasswordUtils;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;

/**
 * Static authentication facade for LazySpringSecurity.
 *
 * Provides static access to authentication operations from anywhere
 * in the codebase, without requiring dependency injection.
 *
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * // Check if authenticated
 * if (Auth.check()) { ... }
 *
 * // Get current user
 * LazyUser user = Auth.user();
 *
 * // Check roles
 * if (Auth.hasRole("ADMIN")) { ... }
 *
 * // Get user ID
 * String id = Auth.id();
 *
 * // Execute action only if authenticated
 * Auth.ifAuthenticated(user -> {
 *     System.out.println("Hello, " + user.getUsername());
 * });
 * }</pre>
 *
 * @author Sudojed Team
 * @see LazySecurityContext
 * @see LazyUser
 */
public final class Auth {

    // Authentication provider (for login operations)
    private static AuthProvider provider;

    // Token blacklist for revocation
    private static TokenBlacklist tokenBlacklist;

    // Current token ID (set by JwtFilter)
    private static final ThreadLocal<String> currentTokenId =
        new ThreadLocal<>();
    private static final ThreadLocal<Instant> currentTokenIssuedAt =
        new ThreadLocal<>();

    private Auth() {
        // Utility class - do not instantiate
    }

    // ========================================================================
    // AUTHENTICATION CHECKS
    // ========================================================================

    /**
     * Checks if there is an authenticated user.
     *
     * @return true if authenticated
     */
    public static boolean check() {
        return LazySecurityContext.isAuthenticated();
    }

    /**
     * Checks if the user is a guest (not authenticated).
     *
     * @return true if NOT authenticated
     */
    public static boolean guest() {
        return !check();
    }

    // ========================================================================
    // USER ACCESS
    // ========================================================================

    /**
     * Gets the current authenticated user.
     *
     * @return current LazyUser or anonymous user if not authenticated
     */
    public static LazyUser user() {
        return LazySecurityContext.getCurrentUser();
    }

    /**
     * Gets the user as Optional (empty if not authenticated).
     *
     * @return Optional with user or empty
     */
    public static Optional<LazyUser> userOptional() {
        return LazySecurityContext.getUser();
    }

    /**
     * Gets the authenticated user's ID.
     *
     * @return user ID or null if not authenticated
     */
    public static String id() {
        return check() ? user().getId() : null;
    }

    /**
     * Gets the authenticated user's username.
     *
     * @return username or null if not authenticated
     */
    public static String username() {
        return check() ? user().getUsername() : null;
    }

    // ========================================================================
    // ROLE AND PERMISSION CHECKS
    // ========================================================================

    /**
     * Checks if the user has a specific role.
     *
     * @param role role name (e.g., "ADMIN", "MANAGER")
     * @return true if has the role
     */
    public static boolean hasRole(String role) {
        return LazySecurityContext.hasRole(role);
    }

    /**
     * Checks if the user has any of the specified roles.
     *
     * @param roles array of roles
     * @return true if has at least one
     */
    public static boolean hasAnyRole(String... roles) {
        return LazySecurityContext.hasAnyRole(roles);
    }

    /**
     * Checks if the user has all the specified roles.
     *
     * @param roles array of roles
     * @return true if has all
     */
    public static boolean hasAllRoles(String... roles) {
        return LazySecurityContext.hasAllRoles(roles);
    }

    /**
     * Checks if the user has a specific permission.
     *
     * @param permission permission name
     * @return true if has the permission
     */
    public static boolean can(String permission) {
        return LazySecurityContext.hasPermission(permission);
    }

    /**
     * Checks if the user does NOT have a permission.
     *
     * @param permission permission name
     * @return true if does NOT have the permission
     */
    public static boolean cannot(String permission) {
        return !can(permission);
    }

    /**
     * Checks if the user is an admin.
     *
     * @return true if has ADMIN role
     */
    public static boolean isAdmin() {
        return LazySecurityContext.isAdmin();
    }

    // ========================================================================
    // AUTHENTICATION (LOGIN/LOGOUT)
    // ========================================================================

    /**
     * Attempts to authenticate with credentials.
     *
     * @param username username
     * @param password plain text password
     * @return true if successfully authenticated
     */
    public static boolean attempt(String username, String password) {
        if (provider == null) {
            throw new IllegalStateException(
                "AuthProvider not configured. Configure via Auth.setProvider()"
            );
        }
        return provider.attempt(username, password);
    }

    /**
     * Validates credentials without logging in.
     *
     * @param username username
     * @param password plain text password
     * @return true if credentials are valid
     */
    public static boolean validate(String username, String password) {
        if (provider == null) {
            throw new IllegalStateException(
                "AuthProvider not configured. Configure via Auth.setProvider()"
            );
        }
        return provider.validate(username, password);
    }

    /**
     * Authenticates a user directly (without verifying password).
     * Useful after registration or password recovery.
     *
     * @param user user to authenticate
     */
    public static void login(LazyUser user) {
        LazySecurityContext.setCurrentUser(user);
    }

    /**
     * Logs out the current user.
     */
    public static void logout() {
        LazySecurityContext.clear();
    }

    // ========================================================================
    // TOKEN REVOCATION
    // ========================================================================

    /**
     * Revokes the current token (logout current session only).
     * The token will be blacklisted until its natural expiration.
     */
    public static void revokeCurrentToken() {
        if (tokenBlacklist == null) {
            throw new IllegalStateException(
                "TokenBlacklist not configured. Configure via Auth.setTokenBlacklist()"
            );
        }

        String tokenId = currentTokenId.get();
        if (tokenId != null && !tokenId.isEmpty()) {
            // Blacklist for 24 hours (or until token expiration)
            tokenBlacklist.blacklist(tokenId, java.time.Duration.ofHours(24));
        }

        logout();
    }

    /**
     * Revokes all tokens for the current user (logout from all devices).
     */
    public static void revokeAllTokens() {
        if (tokenBlacklist == null) {
            throw new IllegalStateException(
                "TokenBlacklist not configured. Configure via Auth.setTokenBlacklist()"
            );
        }

        String userId = id();
        if (userId != null && !userId.isEmpty()) {
            tokenBlacklist.blacklistAllForUser(userId);
        }

        logout();
    }

    /**
     * Revokes all tokens for a specific user (admin action).
     *
     * @param userId The user ID whose tokens should be revoked
     */
    public static void revokeTokensForUser(String userId) {
        if (tokenBlacklist == null) {
            throw new IllegalStateException(
                "TokenBlacklist not configured. Configure via Auth.setTokenBlacklist()"
            );
        }

        if (userId != null && !userId.isEmpty()) {
            tokenBlacklist.blacklistAllForUser(userId);
        }
    }

    /**
     * Checks if the current token has been revoked.
     *
     * @return true if the current token is blacklisted
     */
    public static boolean isCurrentTokenRevoked() {
        if (tokenBlacklist == null) {
            return false;
        }

        String tokenId = currentTokenId.get();
        if (tokenId != null && !tokenId.isEmpty()) {
            if (tokenBlacklist.isBlacklisted(tokenId)) {
                return true;
            }
        }

        // Check user-wide blacklist
        String userId = id();
        Instant issuedAt = currentTokenIssuedAt.get();
        if (userId != null && issuedAt != null) {
            return tokenBlacklist.isUserBlacklistedAt(userId, issuedAt);
        }

        return false;
    }

    /**
     * Sets the current token information (called by JwtFilter).
     *
     * @param tokenId The JWT ID (jti claim)
     * @param issuedAt When the token was issued
     */
    public static void setCurrentToken(String tokenId, Instant issuedAt) {
        currentTokenId.set(tokenId);
        currentTokenIssuedAt.set(issuedAt);
    }

    /**
     * Clears the current token information.
     */
    public static void clearCurrentToken() {
        currentTokenId.remove();
        currentTokenIssuedAt.remove();
    }

    /**
     * Gets the token blacklist.
     *
     * @return The token blacklist, or null if not configured
     */
    public static TokenBlacklist getTokenBlacklist() {
        return tokenBlacklist;
    }

    // ========================================================================
    // UTILITIES
    // ========================================================================

    /**
     * Executes action only if authenticated.
     *
     * @param action action to execute with the user
     */
    public static void ifAuthenticated(
        java.util.function.Consumer<LazyUser> action
    ) {
        if (check()) {
            action.accept(user());
        }
    }

    /**
     * Executes action only if guest.
     *
     * @param action action to execute
     */
    public static void ifGuest(Runnable action) {
        if (guest()) {
            action.run();
        }
    }

    /**
     * Gets value if authenticated, or default if not.
     *
     * @param mapper function to extract value from user
     * @param defaultValue default value
     * @return extracted value or default
     */
    public static <T> T getOrDefault(
        Function<LazyUser, T> mapper,
        T defaultValue
    ) {
        return check() ? mapper.apply(user()) : defaultValue;
    }

    /**
     * Gets a claim from the user.
     *
     * @param key claim name
     * @return claim value or null
     */
    public static Object claim(String key) {
        return user().getClaim(key);
    }

    /**
     * Gets a claim from the user with type.
     *
     * @param key claim name
     * @param defaultValue default value if claim doesn't exist
     * @return claim value or default
     */
    public static <T> T claim(String key, T defaultValue) {
        return user().getClaim(key, defaultValue);
    }

    /**
     * Requires authentication. Throws exception if not authenticated.
     *
     * @throws UnauthorizedException if not authenticated
     */
    public static void requireAuth() {
        if (!check()) {
            throw new UnauthorizedException("Authentication required");
        }
    }

    /**
     * Requires a specific role.
     *
     * @param role required role
     * @throws ao.sudojed.lss.exception.AccessDeniedException if doesn't have the role
     */
    public static void requireRole(String role) {
        requireAuth();
        if (!hasRole(role)) {
            throw new ao.sudojed.lss.exception.AccessDeniedException(
                "Required role: " + role
            );
        }
    }

    /**
     * Executes as another user (for testing).
     *
     * @param user user to impersonate
     * @param action action to execute
     * @return action result
     */
    public static <T> T runAs(
        LazyUser user,
        java.util.function.Supplier<T> action
    ) {
        return LazySecurityContext.runAs(user, action);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * Configures the authentication provider.
     *
     * @param authProvider provider implementation
     */
    public static void setProvider(AuthProvider authProvider) {
        provider = authProvider;
    }

    /**
     * Configures the token blacklist for revocation support.
     *
     * @param blacklist The token blacklist implementation
     */
    public static void setTokenBlacklist(TokenBlacklist blacklist) {
        tokenBlacklist = blacklist;
    }

    /**
     * Interface for custom authentication provider.
     */
    @FunctionalInterface
    public interface AuthProvider {
        /**
         * Attempts to authenticate with credentials.
         *
         * @param username username
         * @param password password
         * @return true if successful
         */
        boolean attempt(String username, String password);

        /**
         * Validates credentials without logging in.
         * By default, just calls attempt.
         */
        default boolean validate(String username, String password) {
            return attempt(username, password);
        }
    }

    // ========================================================================
    // PASSWORD HELPERS
    // ========================================================================

    /**
     * Hashes a password.
     *
     * @param password plain text password
     * @return password hash
     */
    public static String hashPassword(String password) {
        return PasswordUtils.hash(password);
    }

    /**
     * Verifies if password matches the hash.
     *
     * @param password plain text password
     * @param hash stored hash
     * @return true if matches
     */
    public static boolean checkPassword(String password, String hash) {
        return PasswordUtils.matches(password, hash);
    }
}
