package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Unified security annotation for protecting endpoints and methods.
 * Provides a single, intuitive API for all authorization needs.
 *
 * <h2>Basic Authentication (any authenticated user)</h2>
 * <pre>{@code
 * @Secured
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 *
 * <h2>Single Role</h2>
 * <pre>{@code
 * @Secured("ADMIN")
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 * }</pre>
 *
 * <h2>Multiple Roles (ANY - default)</h2>
 * <pre>{@code
 * @Secured({"ADMIN", "MANAGER"})
 * @GetMapping("/reports")
 * public List<Report> getReports() { }
 * }</pre>
 *
 * <h2>Multiple Roles (ALL required)</h2>
 * <pre>{@code
 * @Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
 * @GetMapping("/premium-content")
 * public Content getPremiumContent() { }
 * }</pre>
 *
 * <h2>With Permissions</h2>
 * <pre>{@code
 * @Secured(permissions = "users:read")
 * @GetMapping("/users")
 * public List<User> listUsers() { }
 *
 * @Secured(value = "USER", permissions = {"posts:read", "posts:write"})
 * @PostMapping("/posts")
 * public Post createPost() { }
 * }</pre>
 *
 * <h2>With SpEL Condition</h2>
 * <pre>{@code
 * @Secured(condition = "#userId == principal.id")
 * @GetMapping("/users/{userId}/settings")
 * public Settings getUserSettings(@PathVariable Long userId) { }
 * }</pre>
 *
 * <h2>Class-Level Security</h2>
 * <pre>{@code
 * @Secured("ADMIN")
 * @RestController
 * @RequestMapping("/api/admin")
 * public class AdminController {
 *     // All endpoints require ADMIN role
 * }
 * }</pre>
 *
 * @author Sudojed Team
 * @since 1.0.0
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Secured {
    /**
     * Roles allowed to access the resource.
     * If empty, only authentication is required (any authenticated user).
     *
     * <p>This is the default attribute, so you can use:</p>
     * <ul>
     *   <li>{@code @Secured} - any authenticated user</li>
     *   <li>{@code @Secured("ADMIN")} - requires ADMIN role</li>
     *   <li>{@code @Secured({"ADMIN", "MANAGER"})} - requires any of these roles</li>
     * </ul>
     */
    String[] value() default {};

    /**
     * Alias for {@link #value()} - for semantic clarity when using other attributes.
     *
     * <p>Example:</p>
     * <pre>{@code
     * @Secured(roles = "USER", permissions = "posts:write")
     * }</pre>
     */
    String[] roles() default {};

    /**
     * Specific permissions required (fine-grained access control).
     *
     * <p>Examples: "users:read", "posts:write", "admin:manage"</p>
     *
     * <p>When multiple permissions are specified, ANY of them is sufficient
     * (OR logic) unless combined with roles using {@link #all()}.</p>
     */
    String[] permissions() default {};

    /**
     * When {@code true}, ALL specified roles are required (AND logic).
     * When {@code false} (default), ANY of the roles is sufficient (OR logic).
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // User needs VERIFIED OR PREMIUM (default)
     * @Secured({"VERIFIED", "PREMIUM"})
     *
     * // User needs VERIFIED AND PREMIUM
     * @Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
     * }</pre>
     */
    boolean all() default false;

    /**
     * Custom error message when access is denied.
     */
    String message() default "Access denied";

    /**
     * SpEL expression for dynamic authorization.
     *
     * <p>Available variables:</p>
     * <ul>
     *   <li>{@code principal} - the current LazyUser</li>
     *   <li>{@code authentication} - full authentication object</li>
     *   <li>Method parameters by name (e.g., {@code #userId})</li>
     * </ul>
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // User can only access their own resources
     * @Secured(condition = "#userId == principal.id")
     *
     * // Custom business logic
     * @Secured(condition = "principal.hasPermission('admin') or #entity.createdBy == principal.id")
     * }</pre>
     */
    String condition() default "";
}
