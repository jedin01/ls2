package ao.sudojed.lss.aspect;

import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.annotation.Owner;
import ao.sudojed.lss.annotation.Secured;
import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.AccessDeniedException;
import ao.sudojed.lss.exception.UnauthorizedException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;

/**
 * Aspect that intercepts methods annotated with @Secured, @LazySecured (deprecated),
 * @Public, @Owner, etc. Performs authorization checks automatically.
 *
 * @author Sudojed Team
 */
@Aspect
@Order(100)
public class LazySecurityAspect {

    private static final Logger log = LoggerFactory.getLogger(
        LazySecurityAspect.class
    );

    /**
     * Intercepts methods annotated with @Secured (primary annotation).
     * Also intercepts @Admin and @Authenticated which are meta-annotated with @Secured.
     */
    @Before(
        "@annotation(ao.sudojed.lss.annotation.Secured) || " +
            "@within(ao.sudojed.lss.annotation.Secured) || " +
            "@annotation(ao.sudojed.lss.annotation.Admin) || " +
            "@within(ao.sudojed.lss.annotation.Admin) || " +
            "@annotation(ao.sudojed.lss.annotation.Authenticated) || " +
            "@within(ao.sudojed.lss.annotation.Authenticated)"
    )
    public void checkSecured(JoinPoint joinPoint) {
        Secured annotation = getAnnotation(joinPoint, Secured.class);

        if (annotation == null) {
            return;
        }

        LazyUser user = LazySecurityContext.getCurrentUser();

        // Verify authentication
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }

        // Get roles from value() or roles() attribute
        String[] roles =
            annotation.value().length > 0
                ? annotation.value()
                : annotation.roles();

        if (roles.length > 0) {
            boolean hasRole = annotation.all()
                ? user.hasAllRoles(roles)
                : user.hasAnyRole(roles);

            if (!hasRole) {
                log.debug(
                    "Access denied for user {} - required roles: {}, user roles: {}",
                    user.getUsername(),
                    Arrays.toString(roles),
                    user.getRoles()
                );
                throw new AccessDeniedException(annotation.message());
            }
        }

        // Verify permissions
        String[] permissions = annotation.permissions();
        if (permissions.length > 0) {
            boolean hasPermission = Arrays.stream(permissions).anyMatch(
                user::hasPermission
            );

            if (!hasPermission) {
                log.debug(
                    "Access denied for user {} - required permissions: {}",
                    user.getUsername(),
                    Arrays.toString(permissions)
                );
                throw new AccessDeniedException(annotation.message());
            }
        }

        log.debug(
            "Access granted for user {} to {}.{}",
            user.getUsername(),
            joinPoint.getTarget().getClass().getSimpleName(),
            joinPoint.getSignature().getName()
        );
    }

    /**
     * Intercepts methods annotated with @LazySecured (deprecated - kept for backward compatibility).
     *
     * @deprecated Use @Secured instead
     */
    @Before(
        "@annotation(ao.sudojed.lss.annotation.LazySecured) || " +
            "@within(ao.sudojed.lss.annotation.LazySecured)"
    )
    public void checkLazySecured(JoinPoint joinPoint) {
        LazySecured annotation = getAnnotation(joinPoint, LazySecured.class);

        if (annotation == null) {
            return;
        }

        LazyUser user = LazySecurityContext.getCurrentUser();

        // Verify authentication
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }

        // Verify roles
        String[] roles = annotation.roles();
        if (roles.length > 0) {
            boolean hasRole = switch (annotation.logic()) {
                case ANY -> user.hasAnyRole(roles);
                case ALL -> user.hasAllRoles(roles);
            };

            if (!hasRole) {
                log.debug(
                    "Access denied for user {} - required roles: {}, user roles: {}",
                    user.getUsername(),
                    Arrays.toString(roles),
                    user.getRoles()
                );
                throw new AccessDeniedException(annotation.message());
            }
        }

        // Verify permissions
        String[] permissions = annotation.permissions();
        if (permissions.length > 0) {
            boolean hasPermission = Arrays.stream(permissions).anyMatch(
                user::hasPermission
            );

            if (!hasPermission) {
                log.debug(
                    "Access denied for user {} - required permissions: {}",
                    user.getUsername(),
                    Arrays.toString(permissions)
                );
                throw new AccessDeniedException(annotation.message());
            }
        }

        log.debug(
            "Access granted for user {} to {}.{}",
            user.getUsername(),
            joinPoint.getTarget().getClass().getSimpleName(),
            joinPoint.getSignature().getName()
        );
    }

    /**
     * Intercepts methods annotated with @Owner.
     */
    @Before("@annotation(ao.sudojed.lss.annotation.Owner)")
    public void checkOwnership(JoinPoint joinPoint) {
        Owner annotation = getAnnotation(joinPoint, Owner.class);

        if (annotation == null) {
            return;
        }

        LazyUser user = LazySecurityContext.getCurrentUser();

        // Verify authentication
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }

        // Admin bypass
        if (annotation.adminBypass() && user.isAdmin()) {
            log.debug(
                "Admin bypass for ownership check - user: {}",
                user.getUsername()
            );
            return;
        }

        // Bypass by specific roles
        for (String role : annotation.bypassRoles()) {
            if (user.hasRole(role)) {
                log.debug(
                    "Role bypass for ownership check - user: {}, role: {}",
                    user.getUsername(),
                    role
                );
                return;
            }
        }

        // Extract the ownership field value from the arguments
        Object resourceOwnerId = extractFieldValue(
            joinPoint,
            annotation.field()
        );
        String currentUserId = user.getId();

        if (resourceOwnerId == null) {
            throw new AccessDeniedException(
                "Could not determine resource owner"
            );
        }

        if (!String.valueOf(resourceOwnerId).equals(currentUserId)) {
            log.debug(
                "Ownership check failed - user: {}, resource owner: {}",
                currentUserId,
                resourceOwnerId
            );
            throw new AccessDeniedException(annotation.message());
        }

        log.debug(
            "Ownership check passed - user: {} is owner of resource",
            currentUserId
        );
    }

    /**
     * @Public methods don't need verification (bypass).
     */
    @Before(
        "@annotation(ao.sudojed.lss.annotation.Public) || @within(ao.sudojed.lss.annotation.Public)"
    )
    public void handlePublic(JoinPoint joinPoint) {
        // Does nothing - just ensures the method is not blocked
        log.debug(
            "Public access granted to {}.{}",
            joinPoint.getTarget().getClass().getSimpleName(),
            joinPoint.getSignature().getName()
        );
    }

    /**
     * Extracts annotation from method or class.
     */
    @SuppressWarnings("unchecked")
    private <T extends Annotation> T getAnnotation(
        JoinPoint joinPoint,
        Class<T> annotationType
    ) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // First try on the method
        T annotation = AnnotationUtils.findAnnotation(method, annotationType);
        if (annotation != null) {
            return annotation;
        }

        // Then try on the class
        return AnnotationUtils.findAnnotation(
            joinPoint.getTarget().getClass(),
            annotationType
        );
    }

    /**
     * Extracts field value from method arguments.
     */
    private Object extractFieldValue(JoinPoint joinPoint, String fieldName) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] parameterNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();

        // Search by parameter name
        for (int i = 0; i < parameterNames.length; i++) {
            if (parameterNames[i].equals(fieldName)) {
                return args[i];
            }
        }

        // Search in @PathVariable, @RequestParam annotations, etc.
        Method method = signature.getMethod();
        Parameter[] parameters = method.getParameters();

        for (int i = 0; i < parameters.length; i++) {
            // Check if the annotation parameter name matches
            if (hasMatchingAnnotation(parameters[i], fieldName)) {
                return args[i];
            }
        }

        return null;
    }

    private boolean hasMatchingAnnotation(
        Parameter parameter,
        String fieldName
    ) {
        // Check @PathVariable
        try {
            Class<?> pathVariableClass = Class.forName(
                "org.springframework.web.bind.annotation.PathVariable"
            );
            Annotation pathVariable = parameter.getAnnotation(
                (Class<? extends Annotation>) pathVariableClass
            );
            if (pathVariable != null) {
                String value = (String) pathVariableClass
                    .getMethod("value")
                    .invoke(pathVariable);
                String name = (String) pathVariableClass
                    .getMethod("name")
                    .invoke(pathVariable);
                if (fieldName.equals(value) || fieldName.equals(name)) {
                    return true;
                }
            }
        } catch (Exception ignored) {}

        // Check @RequestParam
        try {
            Class<?> requestParamClass = Class.forName(
                "org.springframework.web.bind.annotation.RequestParam"
            );
            Annotation requestParam = parameter.getAnnotation(
                (Class<? extends Annotation>) requestParamClass
            );
            if (requestParam != null) {
                String value = (String) requestParamClass
                    .getMethod("value")
                    .invoke(requestParam);
                String name = (String) requestParamClass
                    .getMethod("name")
                    .invoke(requestParam);
                if (fieldName.equals(value) || fieldName.equals(name)) {
                    return true;
                }
            }
        } catch (Exception ignored) {}

        return false;
    }
}
