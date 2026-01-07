package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Validates that the current user is the owner of the resource.
 * Useful for endpoints where users can only access their own data.
 *
 * <h2>Basic Usage (Path Variable)</h2>
 * <pre>{@code
 * @Owner(field = "userId")
 * @GetMapping("/users/{userId}/orders")
 * public List<Order> getUserOrders(@PathVariable Long userId) { }
 * }</pre>
 *
 * <h2>With Admin Bypass</h2>
 * <pre>{@code
 * @Owner(field = "id", adminBypass = true)
 * @PutMapping("/users/{id}")
 * public User updateUser(@PathVariable Long id, @RequestBody User user) {
 *     // User can only edit their own profile
 *     // Admin can edit any profile
 * }
 * }</pre>
 *
 * <h2>Entity-Level Ownership (verify returned entity)</h2>
 * <pre>{@code
 * @Owner(entityField = "createdBy")
 * @GetMapping("/posts/{id}")
 * public Post getPost(@PathVariable Long id) {
 *     // Verifies that returned Post.createdBy matches current user
 * }
 * }</pre>
 *
 * <h2>Request Body Ownership (verify request body)</h2>
 * <pre>{@code
 * @Owner(requestField = "authorId")
 * @PostMapping("/posts")
 * public Post createPost(@RequestBody Post post) {
 *     // Verifies that post.authorId matches current user
 * }
 * }</pre>
 *
 * <h2>Combined Verification</h2>
 * <pre>{@code
 * @Owner(field = "userId", entityField = "ownerId")
 * @PutMapping("/users/{userId}/posts/{postId}")
 * public Post updatePost(@PathVariable String userId, @PathVariable Long postId) {
 *     // Verifies both path variable AND returned entity ownership
 * }
 * }</pre>
 *
 * @author Sudojed Team
 * @since 1.0.0
 */
@Target({ ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Owner {
    /**
     * Name of the path variable or request parameter that contains the owner ID.
     * Used for pre-execution verification.
     *
     * <p>Example: {@code @Owner(field = "userId")} checks if path variable
     * {@code userId} matches the current user's ID.</p>
     *
     * <p>Default: "" (not used)</p>
     */
    String field() default "";

    /**
     * Field name in the returned entity that contains the owner ID.
     * Used for post-execution verification on the response.
     *
     * <p>Example: {@code @Owner(entityField = "createdBy")} checks if the
     * returned entity's {@code createdBy} field matches the current user's ID.</p>
     *
     * <p>Default: "" (not used)</p>
     */
    String entityField() default "";

    /**
     * Field name in the request body that contains the owner ID.
     * Used for pre-execution verification on the request.
     *
     * <p>Example: {@code @Owner(requestField = "authorId")} checks if the
     * request body's {@code authorId} field matches the current user's ID.</p>
     *
     * <p>Default: "" (not used)</p>
     */
    String requestField() default "";

    /**
     * Field of the principal (LazyUser) that contains the user ID for comparison.
     *
     * <p>Default: "id" (uses {@code LazyUser.getId()})</p>
     */
    String principalField() default "id";

    /**
     * Roles that can bypass the ownership verification entirely.
     *
     * <p>Default: {"ADMIN"}</p>
     */
    String[] bypassRoles() default { "ADMIN" };

    /**
     * Allows users with ADMIN role to bypass the verification.
     * This is a convenience shortcut for {@code bypassRoles = {"ADMIN"}}.
     *
     * <p>Default: true</p>
     */
    boolean adminBypass() default true;

    /**
     * Whether to verify ownership on the response entity (post-execution).
     * When true and {@code entityField} is set, the returned entity will be
     * checked for ownership after the method executes.
     *
     * <p>Default: true</p>
     */
    boolean verifyResponse() default true;

    /**
     * Whether to allow null/empty owner IDs in the resource.
     * When true, resources without an owner ID will be accessible.
     * When false, resources without an owner ID will be denied.
     *
     * <p>Default: false</p>
     */
    boolean allowNullOwner() default false;

    /**
     * Error message when ownership verification fails.
     */
    String message() default "You can only access your own resources";

    /**
     * HTTP status code to return when ownership verification fails.
     *
     * <p>Default: 403 (Forbidden)</p>
     */
    int statusCode() default 403;
}
