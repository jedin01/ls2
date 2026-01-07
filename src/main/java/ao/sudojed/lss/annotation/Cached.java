package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for security-aware response caching.
 * Unlike standard caching, this annotation respects the security context
 * to prevent data leaks between users.
 *
 * <h2>Basic Usage (Cache per User)</h2>
 * <pre>{@code
 * @Cached(ttl = 60)
 * @Secured
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 *
 * <h2>Global Cache (Public Data Only)</h2>
 * <pre>{@code
 * @Cached(ttl = 300, perUser = false)
 * @Public
 * @GetMapping("/products")
 * public List<Product> getProducts() { }
 * }</pre>
 *
 * <h2>Cache per Role</h2>
 * <pre>{@code
 * @Cached(ttl = 120, perRole = true)
 * @Secured({"ADMIN", "MANAGER"})
 * @GetMapping("/reports")
 * public List<Report> getReports() { }
 * }</pre>
 *
 * <h2>Conditional Caching</h2>
 * <pre>{@code
 * @Cached(ttl = 60, condition = "#result != null && #result.size() > 0")
 * @Secured
 * @GetMapping("/data")
 * public List<Data> getData() { }
 * }</pre>
 *
 * <h2>Disable Caching for Sensitive Data</h2>
 * <pre>{@code
 * @Cached(enabled = false)
 * @Secured
 * @GetMapping("/bank-statement")
 * public Statement getStatement() { }
 * }</pre>
 *
 * @author Sudojed Team
 * @since 1.1.0
 */
@Target({ ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Cached {

    /**
     * Time-to-live for cached entries in seconds.
     *
     * <p>Default: 60 seconds</p>
     */
    int ttl() default 60;

    /**
     * Whether caching is enabled for this method.
     * Set to false to explicitly disable caching.
     *
     * <p>Default: true</p>
     */
    boolean enabled() default true;

    /**
     * Whether to cache responses per user.
     * When true, each user gets their own cached response.
     * When false, the response is cached globally (use only for public data).
     *
     * <p>Default: true</p>
     */
    boolean perUser() default true;

    /**
     * Whether to cache responses per role.
     * When true, users with different roles get different cached responses.
     * Useful when the same endpoint returns different data based on roles.
     *
     * <p>Default: false</p>
     */
    boolean perRole() default false;

    /**
     * Custom cache key prefix.
     * If not specified, the method signature is used.
     *
     * <p>Example: "user-profile", "product-list"</p>
     */
    String key() default "";

    /**
     * SpEL condition that must evaluate to true for the response to be cached.
     * Has access to #result (the method return value) and method parameters.
     *
     * <p>Example: "#result != null", "#result.size() > 0"</p>
     */
    String condition() default "";

    /**
     * SpEL condition that, if true, prevents caching (even if condition passes).
     *
     * <p>Example: "#result.isEmpty()", "#userId == 'admin'"</p>
     */
    String unless() default "";

    /**
     * Whether to include query parameters in the cache key.
     * When true, different query parameter combinations result in different cache entries.
     *
     * <p>Default: true</p>
     */
    boolean includeParams() default true;

    /**
     * Parameter names to exclude from the cache key.
     * Useful for parameters that don't affect the response (e.g., tracking IDs).
     *
     * <p>Example: {"_t", "trackingId", "requestId"}</p>
     */
    String[] excludeParams() default {};

    /**
     * Cache name/region for grouping related cache entries.
     * Useful for cache management and selective invalidation.
     *
     * <p>Default: "default"</p>
     */
    String cacheName() default "default";

    /**
     * Whether to synchronize cache access to prevent cache stampede.
     * When true, only one thread will compute the value while others wait.
     *
     * <p>Default: false</p>
     */
    boolean sync() default false;

    /**
     * Maximum number of entries to store in this cache.
     * Only applicable for in-memory caching.
     * 0 means unlimited (subject to global limits).
     *
     * <p>Default: 0 (unlimited)</p>
     */
    int maxSize() default 0;

    /**
     * Headers to include in the cache key.
     * Useful when responses vary based on headers (e.g., Accept-Language).
     *
     * <p>Example: {"Accept-Language", "X-Client-Version"}</p>
     */
    String[] varyByHeaders() default {};

    /**
     * Whether to add Cache-Control headers to the HTTP response.
     * When true, appropriate headers are added based on TTL and visibility.
     *
     * <p>Default: true</p>
     */
    boolean addCacheHeaders() default true;
}
