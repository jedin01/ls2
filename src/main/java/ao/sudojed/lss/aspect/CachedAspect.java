package ao.sudojed.lss.aspect;

import ao.sudojed.lss.annotation.Cached;
import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Aspect that intercepts methods annotated with @Cached and provides
 * security-aware response caching.
 *
 * <p>Unlike standard caching, this aspect respects the security context
 * to prevent data leaks between users with different permissions.</p>
 *
 * @author Sudojed Team
 * @since 1.1.0
 */
@Aspect
@Order(25)
public class CachedAspect {

    private static final Logger log = LoggerFactory.getLogger(CachedAspect.class);

    private final ExpressionParser expressionParser = new SpelExpressionParser();

    /**
     * In-memory cache storage.
     * Key: cache key, Value: CacheEntry
     */
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    /**
     * Maximum cache size (can be configured).
     */
    private int maxCacheSize = 10000;

    /**
     * Intercepts methods annotated with @Cached.
     */
    @Around("@annotation(cached)")
    public Object handleCached(ProceedingJoinPoint joinPoint, Cached cached) throws Throwable {
        // Check if caching is disabled
        if (!cached.enabled()) {
            return joinPoint.proceed();
        }

        // Generate cache key
        String cacheKey = generateCacheKey(joinPoint, cached);

        // Check cache
        CacheEntry entry = cache.get(cacheKey);
        if (entry != null && !entry.isExpired()) {
            log.debug("Cache hit for key: {}", cacheKey);
            addCacheHeadersToResponse(cached, true);
            return entry.value;
        }

        // Cache miss - execute method
        Object result;
        if (cached.sync()) {
            synchronized (cacheKey.intern()) {
                // Double-check after acquiring lock
                entry = cache.get(cacheKey);
                if (entry != null && !entry.isExpired()) {
                    log.debug("Cache hit (after sync) for key: {}", cacheKey);
                    addCacheHeadersToResponse(cached, true);
                    return entry.value;
                }
                result = joinPoint.proceed();
            }
        } else {
            result = joinPoint.proceed();
        }

        // Check if result should be cached
        if (shouldCache(joinPoint, cached, result)) {
            // Enforce max size
            if (cached.maxSize() > 0 && cache.size() >= cached.maxSize()) {
                evictOldestEntries(cached.cacheName(), cached.maxSize() / 4);
            } else if (cache.size() >= maxCacheSize) {
                evictOldestEntries(null, maxCacheSize / 4);
            }

            // Store in cache
            Instant expiresAt = Instant.now().plus(Duration.ofSeconds(cached.ttl()));
            cache.put(cacheKey, new CacheEntry(result, expiresAt, cached.cacheName()));
            log.debug("Cached result for key: {} (TTL: {}s)", cacheKey, cached.ttl());
        }

        addCacheHeadersToResponse(cached, false);
        return result;
    }

    /**
     * Generates a cache key based on the method, user, and parameters.
     */
    private String generateCacheKey(ProceedingJoinPoint joinPoint, Cached cached) {
        StringBuilder keyBuilder = new StringBuilder();

        // Cache name prefix
        keyBuilder.append(cached.cacheName()).append(":");

        // Custom key or method signature
        if (cached.key() != null && !cached.key().isEmpty()) {
            keyBuilder.append(cached.key());
        } else {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            keyBuilder.append(signature.getDeclaringTypeName())
                      .append(".")
                      .append(signature.getName());
        }

        // Per-user caching
        if (cached.perUser()) {
            LazyUser user = LazySecurityContext.getCurrentUser();
            if (user.isAuthenticated()) {
                keyBuilder.append(":user:").append(user.getId());
            } else {
                keyBuilder.append(":anonymous");
            }
        }

        // Per-role caching
        if (cached.perRole()) {
            LazyUser user = LazySecurityContext.getCurrentUser();
            if (user.isAuthenticated()) {
                String roles = user.getRoles().stream()
                    .sorted()
                    .collect(Collectors.joining(","));
                keyBuilder.append(":roles:").append(roles);
            }
        }

        // Include parameters
        if (cached.includeParams()) {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            String[] paramNames = signature.getParameterNames();
            Object[] args = joinPoint.getArgs();
            Set<String> excluded = Set.of(cached.excludeParams());

            if (paramNames != null && args != null) {
                StringBuilder paramsBuilder = new StringBuilder();
                for (int i = 0; i < paramNames.length; i++) {
                    if (!excluded.contains(paramNames[i]) && args[i] != null) {
                        if (paramsBuilder.length() > 0) {
                            paramsBuilder.append("&");
                        }
                        paramsBuilder.append(paramNames[i])
                                     .append("=")
                                     .append(hashValue(args[i]));
                    }
                }
                if (paramsBuilder.length() > 0) {
                    keyBuilder.append(":params:").append(paramsBuilder);
                }
            }
        }

        // Vary by headers
        String[] varyByHeaders = cached.varyByHeaders();
        if (varyByHeaders.length > 0) {
            try {
                ServletRequestAttributes attrs = (ServletRequestAttributes)
                    RequestContextHolder.getRequestAttributes();
                if (attrs != null && attrs.getRequest() != null) {
                    StringBuilder headersBuilder = new StringBuilder();
                    for (String header : varyByHeaders) {
                        String value = attrs.getRequest().getHeader(header);
                        if (value != null) {
                            if (headersBuilder.length() > 0) {
                                headersBuilder.append("&");
                            }
                            headersBuilder.append(header).append("=").append(value.hashCode());
                        }
                    }
                    if (headersBuilder.length() > 0) {
                        keyBuilder.append(":headers:").append(headersBuilder);
                    }
                }
            } catch (Exception e) {
                log.trace("Could not get headers for cache key: {}", e.getMessage());
            }
        }

        return keyBuilder.toString();
    }

    /**
     * Generates a hash for a parameter value.
     */
    private String hashValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String || isPrimitive(value.getClass())) {
            return String.valueOf(value);
        }
        // For complex objects, use hashCode
        return String.valueOf(value.hashCode());
    }

    /**
     * Checks if the result should be cached based on conditions.
     */
    private boolean shouldCache(ProceedingJoinPoint joinPoint, Cached cached, Object result) {
        // Check condition
        String condition = cached.condition();
        if (condition != null && !condition.isEmpty()) {
            if (!evaluateCondition(condition, joinPoint, result)) {
                log.debug("Cache condition not met: {}", condition);
                return false;
            }
        }

        // Check unless
        String unless = cached.unless();
        if (unless != null && !unless.isEmpty()) {
            if (evaluateCondition(unless, joinPoint, result)) {
                log.debug("Cache unless condition matched: {}", unless);
                return false;
            }
        }

        return true;
    }

    /**
     * Evaluates a SpEL condition.
     */
    private boolean evaluateCondition(String condition, ProceedingJoinPoint joinPoint, Object result) {
        try {
            StandardEvaluationContext context = new StandardEvaluationContext();

            // Add result
            context.setVariable("result", result);

            // Add method parameters
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            String[] paramNames = signature.getParameterNames();
            Object[] args = joinPoint.getArgs();

            if (paramNames != null) {
                for (int i = 0; i < paramNames.length; i++) {
                    context.setVariable(paramNames[i], args[i]);
                }
            }

            // Add user context
            LazyUser user = LazySecurityContext.getCurrentUser();
            context.setVariable("user", user);
            context.setVariable("principal", user);

            Expression expression = expressionParser.parseExpression(condition);
            Boolean value = expression.getValue(context, Boolean.class);
            return value != null && value;
        } catch (Exception e) {
            log.warn("Failed to evaluate cache condition '{}': {}", condition, e.getMessage());
            return false;
        }
    }

    /**
     * Adds cache-related HTTP headers to the response.
     */
    private void addCacheHeadersToResponse(Cached cached, boolean cacheHit) {
        if (!cached.addCacheHeaders()) {
            return;
        }

        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes();
            if (attrs != null && attrs.getResponse() != null) {
                var response = attrs.getResponse();

                // Add Cache-Control header
                if (cached.perUser()) {
                    response.setHeader("Cache-Control", "private, max-age=" + cached.ttl());
                } else {
                    response.setHeader("Cache-Control", "public, max-age=" + cached.ttl());
                }

                // Add custom header indicating cache status
                response.setHeader("X-Cache", cacheHit ? "HIT" : "MISS");
            }
        } catch (Exception e) {
            log.trace("Could not add cache headers: {}", e.getMessage());
        }
    }

    /**
     * Evicts oldest entries from the cache.
     */
    private void evictOldestEntries(String cacheName, int count) {
        cache.entrySet().stream()
            .filter(e -> cacheName == null || e.getValue().cacheName.equals(cacheName))
            .sorted((a, b) -> a.getValue().createdAt.compareTo(b.getValue().createdAt))
            .limit(count)
            .forEach(e -> cache.remove(e.getKey()));

        log.debug("Evicted {} cache entries", count);
    }

    /**
     * Evicts all expired entries from the cache.
     *
     * @return The number of entries evicted
     */
    public int evictExpired() {
        int sizeBefore = cache.size();
        cache.entrySet().removeIf(e -> e.getValue().isExpired());
        int evicted = sizeBefore - cache.size();
        if (evicted > 0) {
            log.debug("Evicted {} expired cache entries", evicted);
        }
        return evicted;
    }

    /**
     * Evicts all entries for a specific cache name.
     *
     * @param cacheName The cache name to evict
     * @return The number of entries evicted
     */
    public int evictByName(String cacheName) {
        int sizeBefore = cache.size();
        cache.entrySet().removeIf(e -> e.getValue().cacheName.equals(cacheName));
        int evicted = sizeBefore - cache.size();
        if (evicted > 0) {
            log.debug("Evicted {} cache entries for cache: {}", evicted, cacheName);
        }
        return evicted;
    }

    /**
     * Evicts all entries for a specific user.
     *
     * @param userId The user ID
     * @return The number of entries evicted
     */
    public int evictByUser(String userId) {
        String userKey = ":user:" + userId;
        int sizeBefore = cache.size();
        cache.entrySet().removeIf(e -> e.getKey().contains(userKey));
        int evicted = sizeBefore - cache.size();
        if (evicted > 0) {
            log.debug("Evicted {} cache entries for user: {}", evicted, userId);
        }
        return evicted;
    }

    /**
     * Clears all cache entries.
     */
    public void clearAll() {
        int size = cache.size();
        cache.clear();
        log.info("Cleared all {} cache entries", size);
    }

    /**
     * Gets the current cache size.
     *
     * @return The number of cached entries
     */
    public int size() {
        return cache.size();
    }

    /**
     * Sets the maximum cache size.
     *
     * @param maxSize The maximum number of entries
     */
    public void setMaxCacheSize(int maxSize) {
        this.maxCacheSize = maxSize;
    }

    /**
     * Checks if a class is a primitive or wrapper type.
     */
    private boolean isPrimitive(Class<?> clazz) {
        return clazz.isPrimitive() ||
               clazz == Boolean.class ||
               clazz == Byte.class ||
               clazz == Character.class ||
               clazz == Short.class ||
               clazz == Integer.class ||
               clazz == Long.class ||
               clazz == Float.class ||
               clazz == Double.class ||
               clazz == String.class;
    }

    /**
     * Container for cached values.
     */
    private static class CacheEntry {
        final Object value;
        final Instant expiresAt;
        final Instant createdAt;
        final String cacheName;

        CacheEntry(Object value, Instant expiresAt, String cacheName) {
            this.value = value;
            this.expiresAt = expiresAt;
            this.createdAt = Instant.now();
            this.cacheName = cacheName;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
