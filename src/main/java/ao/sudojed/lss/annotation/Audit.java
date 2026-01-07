package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for automatic security event logging.
 * When applied to a method, it will log access attempts, including
 * user information, action performed, and optional parameters.
 *
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * @Audit
 * @Secured("ADMIN")
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 * }</pre>
 *
 * <h2>With Custom Action Name</h2>
 * <pre>{@code
 * @Audit(action = "USER_DELETE")
 * @Secured("ADMIN")
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 * }</pre>
 *
 * <h2>With Sensitive Level</h2>
 * <pre>{@code
 * @Audit(level = AuditLevel.SENSITIVE)
 * @Secured("ADMIN")
 * @PutMapping("/users/{id}/password")
 * public void resetPassword(@PathVariable Long id) { }
 * }</pre>
 *
 * <h2>Include Parameters in Log</h2>
 * <pre>{@code
 * @Audit(includeParams = true, excludeParams = {"password", "secret"})
 * @PostMapping("/login")
 * public Token login(@RequestBody LoginRequest request) { }
 * }</pre>
 *
 * <h2>Include Response in Log</h2>
 * <pre>{@code
 * @Audit(includeResponse = true)
 * @GetMapping("/reports/export")
 * public byte[] exportData() { }
 * }</pre>
 *
 * @author Sudojed Team
 * @since 1.1.0
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Audit {

    /**
     * Custom action name for the audit log.
     * If not specified, the method name will be used.
     *
     * <p>Example: "USER_DELETE", "PASSWORD_RESET", "DATA_EXPORT"</p>
     */
    String action() default "";

    /**
     * Audit level indicating the sensitivity of the operation.
     *
     * <p>Default: {@link AuditLevel#NORMAL}</p>
     */
    AuditLevel level() default AuditLevel.NORMAL;

    /**
     * Whether to include method parameters in the audit log.
     * Sensitive parameters should be excluded using {@link #excludeParams()}.
     *
     * <p>Default: false</p>
     */
    boolean includeParams() default false;

    /**
     * Parameter names to exclude from the audit log.
     * Useful for sensitive data like passwords, tokens, etc.
     *
     * <p>Example: {"password", "secret", "token", "creditCard"}</p>
     */
    String[] excludeParams() default { "password", "secret", "token", "apiKey", "creditCard" };

    /**
     * Whether to include the response/return value in the audit log.
     * Be careful with large responses or sensitive data.
     *
     * <p>Default: false</p>
     */
    boolean includeResponse() default false;

    /**
     * Whether to log only on successful execution.
     * When false, failures (exceptions) will also be logged.
     *
     * <p>Default: false (log both success and failure)</p>
     */
    boolean onlyOnSuccess() default false;

    /**
     * Custom message template for the audit log.
     * Supports placeholders: {user}, {action}, {method}, {class}, {ip}, {timestamp}
     *
     * <p>Example: "User {user} performed {action} from IP {ip}"</p>
     */
    String message() default "";

    /**
     * Category for grouping audit logs.
     * Useful for filtering and searching logs.
     *
     * <p>Example: "security", "admin", "data", "user"</p>
     */
    String category() default "security";

    /**
     * Audit level enumeration.
     */
    enum AuditLevel {
        /**
         * Low importance - routine operations.
         * Example: viewing public data, listing resources.
         */
        LOW,

        /**
         * Normal importance - standard operations.
         * Example: CRUD operations, user actions.
         */
        NORMAL,

        /**
         * High importance - significant operations.
         * Example: configuration changes, bulk operations.
         */
        HIGH,

        /**
         * Sensitive operations - security-critical.
         * Example: password changes, permission modifications.
         */
        SENSITIVE,

        /**
         * Critical operations - highest priority.
         * Example: admin actions, data deletion, security breaches.
         */
        CRITICAL
    }
}
