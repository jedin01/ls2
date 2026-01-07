package ao.sudojed.lss.jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Interface for JWT token blacklist/revocation functionality.
 * Implementations can store blacklisted tokens in memory, Redis, database, etc.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Blacklist a single token
 * tokenBlacklist.blacklist(tokenId, expiration);
 *
 * // Check if token is blacklisted
 * if (tokenBlacklist.isBlacklisted(tokenId)) {
 *     throw new UnauthorizedException("Token has been revoked");
 * }
 *
 * // Blacklist all tokens for a user
 * tokenBlacklist.blacklistAllForUser(userId);
 * }</pre>
 *
 * @author Sudojed Team
 * @since 1.1.0
 */
public interface TokenBlacklist {

    /**
     * Adds a token to the blacklist.
     *
     * @param tokenId The unique identifier of the token (usually the JWT ID - jti claim)
     * @param expiration When the token would naturally expire (for cleanup purposes)
     */
    void blacklist(String tokenId, Instant expiration);

    /**
     * Adds a token to the blacklist with a TTL.
     *
     * @param tokenId The unique identifier of the token
     * @param ttl How long to keep the token in the blacklist
     */
    void blacklist(String tokenId, Duration ttl);

    /**
     * Checks if a token is blacklisted.
     *
     * @param tokenId The unique identifier of the token
     * @return true if the token is blacklisted, false otherwise
     */
    boolean isBlacklisted(String tokenId);

    /**
     * Removes a token from the blacklist.
     *
     * @param tokenId The unique identifier of the token
     * @return true if the token was removed, false if it wasn't in the blacklist
     */
    boolean remove(String tokenId);

    /**
     * Blacklists all tokens issued before a certain time for a specific user.
     * This is useful for "logout from all devices" functionality.
     *
     * @param userId The user's ID
     * @param issuedBefore Tokens issued before this time will be considered invalid
     */
    void blacklistAllForUser(String userId, Instant issuedBefore);

    /**
     * Blacklists all tokens for a user (using current time as the cutoff).
     * Convenience method for {@link #blacklistAllForUser(String, Instant)}.
     *
     * @param userId The user's ID
     */
    default void blacklistAllForUser(String userId) {
        blacklistAllForUser(userId, Instant.now());
    }

    /**
     * Checks if all tokens for a user issued before a certain time are blacklisted.
     *
     * @param userId The user's ID
     * @param issuedAt When the token was issued
     * @return true if tokens issued at this time for this user are blacklisted
     */
    boolean isUserBlacklistedAt(String userId, Instant issuedAt);

    /**
     * Gets the timestamp before which all tokens for a user are invalid.
     *
     * @param userId The user's ID
     * @return The blacklist timestamp, or empty if no user-wide blacklist exists
     */
    Optional<Instant> getUserBlacklistTimestamp(String userId);

    /**
     * Clears the user-wide blacklist for a specific user.
     *
     * @param userId The user's ID
     */
    void clearUserBlacklist(String userId);

    /**
     * Removes expired entries from the blacklist.
     * Implementations should call this periodically to prevent memory leaks.
     *
     * @return The number of entries removed
     */
    int cleanup();

    /**
     * Gets the total number of blacklisted tokens.
     *
     * @return The count of blacklisted tokens
     */
    int size();

    /**
     * Clears all entries from the blacklist.
     * Use with caution - this will make all previously blacklisted tokens valid again.
     */
    void clear();
}
