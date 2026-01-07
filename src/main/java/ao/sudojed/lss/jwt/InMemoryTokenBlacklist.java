package ao.sudojed.lss.jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory implementation of {@link TokenBlacklist}.
 * Suitable for single-instance deployments or development/testing.
 *
 * <p>For distributed deployments, consider using a Redis-based implementation.</p>
 *
 * <h2>Features</h2>
 * <ul>
 *   <li>Thread-safe using ConcurrentHashMap</li>
 *   <li>Automatic cleanup of expired entries</li>
 *   <li>User-wide blacklisting support</li>
 *   <li>Configurable cleanup interval</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * TokenBlacklist blacklist = new InMemoryTokenBlacklist();
 *
 * // Blacklist a token
 * blacklist.blacklist("token-id-123", Instant.now().plus(Duration.ofHours(1)));
 *
 * // Check if blacklisted
 * if (blacklist.isBlacklisted("token-id-123")) {
 *     // Token is revoked
 * }
 *
 * // Blacklist all user tokens (logout from all devices)
 * blacklist.blacklistAllForUser("user-456");
 * }</pre>
 *
 * @author Sudojed Team
 * @since 1.1.0
 */
public class InMemoryTokenBlacklist implements TokenBlacklist {

    private static final Logger log = LoggerFactory.getLogger(InMemoryTokenBlacklist.class);

    /**
     * Map of token ID to expiration time.
     */
    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();

    /**
     * Map of user ID to the timestamp before which all tokens are invalid.
     */
    private final Map<String, Instant> userBlacklist = new ConcurrentHashMap<>();

    /**
     * Scheduled executor for automatic cleanup.
     */
    private final ScheduledExecutorService cleanupExecutor;

    /**
     * Whether automatic cleanup is enabled.
     */
    private final boolean autoCleanup;

    /**
     * Creates a new InMemoryTokenBlacklist with automatic cleanup enabled.
     * Cleanup runs every 5 minutes by default.
     */
    public InMemoryTokenBlacklist() {
        this(true, Duration.ofMinutes(5));
    }

    /**
     * Creates a new InMemoryTokenBlacklist with configurable cleanup.
     *
     * @param autoCleanup Whether to enable automatic cleanup
     * @param cleanupInterval How often to run cleanup (if enabled)
     */
    public InMemoryTokenBlacklist(boolean autoCleanup, Duration cleanupInterval) {
        this.autoCleanup = autoCleanup;

        if (autoCleanup) {
            this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "token-blacklist-cleanup");
                t.setDaemon(true);
                return t;
            });

            cleanupExecutor.scheduleAtFixedRate(
                this::cleanup,
                cleanupInterval.toMillis(),
                cleanupInterval.toMillis(),
                TimeUnit.MILLISECONDS
            );

            log.debug("InMemoryTokenBlacklist initialized with auto-cleanup every {}", cleanupInterval);
        } else {
            this.cleanupExecutor = null;
            log.debug("InMemoryTokenBlacklist initialized without auto-cleanup");
        }
    }

    @Override
    public void blacklist(String tokenId, Instant expiration) {
        if (tokenId == null || tokenId.isEmpty()) {
            return;
        }
        blacklistedTokens.put(tokenId, expiration);
        log.debug("Token blacklisted: {} (expires: {})", tokenId, expiration);
    }

    @Override
    public void blacklist(String tokenId, Duration ttl) {
        blacklist(tokenId, Instant.now().plus(ttl));
    }

    @Override
    public boolean isBlacklisted(String tokenId) {
        if (tokenId == null || tokenId.isEmpty()) {
            return false;
        }

        Instant expiration = blacklistedTokens.get(tokenId);
        if (expiration == null) {
            return false;
        }

        // Check if the blacklist entry has expired
        if (Instant.now().isAfter(expiration)) {
            // Clean up expired entry
            blacklistedTokens.remove(tokenId);
            return false;
        }

        return true;
    }

    @Override
    public boolean remove(String tokenId) {
        if (tokenId == null || tokenId.isEmpty()) {
            return false;
        }
        Instant removed = blacklistedTokens.remove(tokenId);
        if (removed != null) {
            log.debug("Token removed from blacklist: {}", tokenId);
            return true;
        }
        return false;
    }

    @Override
    public void blacklistAllForUser(String userId, Instant issuedBefore) {
        if (userId == null || userId.isEmpty()) {
            return;
        }
        userBlacklist.put(userId, issuedBefore);
        log.info("All tokens for user {} issued before {} are now blacklisted", userId, issuedBefore);
    }

    @Override
    public boolean isUserBlacklistedAt(String userId, Instant issuedAt) {
        if (userId == null || userId.isEmpty() || issuedAt == null) {
            return false;
        }

        Instant blacklistTime = userBlacklist.get(userId);
        if (blacklistTime == null) {
            return false;
        }

        // Token is blacklisted if it was issued before the blacklist timestamp
        return issuedAt.isBefore(blacklistTime) || issuedAt.equals(blacklistTime);
    }

    @Override
    public Optional<Instant> getUserBlacklistTimestamp(String userId) {
        if (userId == null || userId.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(userBlacklist.get(userId));
    }

    @Override
    public void clearUserBlacklist(String userId) {
        if (userId == null || userId.isEmpty()) {
            return;
        }
        Instant removed = userBlacklist.remove(userId);
        if (removed != null) {
            log.debug("User blacklist cleared for: {}", userId);
        }
    }

    @Override
    public int cleanup() {
        AtomicInteger removed = new AtomicInteger(0);
        Instant now = Instant.now();

        blacklistedTokens.entrySet().removeIf(entry -> {
            if (now.isAfter(entry.getValue())) {
                removed.incrementAndGet();
                return true;
            }
            return false;
        });

        int count = removed.get();
        if (count > 0) {
            log.debug("Cleaned up {} expired blacklist entries", count);
        }

        return count;
    }

    @Override
    public int size() {
        return blacklistedTokens.size();
    }

    @Override
    public void clear() {
        int tokenCount = blacklistedTokens.size();
        int userCount = userBlacklist.size();

        blacklistedTokens.clear();
        userBlacklist.clear();

        log.warn("Token blacklist cleared: {} tokens, {} user blacklists", tokenCount, userCount);
    }

    /**
     * Gets the number of user-wide blacklists.
     *
     * @return The count of users with blacklisted tokens
     */
    public int userBlacklistSize() {
        return userBlacklist.size();
    }

    /**
     * Shuts down the cleanup executor.
     * Should be called when the application is shutting down.
     */
    public void shutdown() {
        if (cleanupExecutor != null && !cleanupExecutor.isShutdown()) {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            log.debug("InMemoryTokenBlacklist shutdown complete");
        }
    }
}
