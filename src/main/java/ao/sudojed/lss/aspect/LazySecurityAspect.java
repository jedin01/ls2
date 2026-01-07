package ao.sudojed.lss.aspect;

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
import java.util.HashSet;
import java.util.Set;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

/**
 * Aspect that intercepts methods annotated with @Secured, @Public, @Owner, etc.
 * Performs authorization checks automatically.
 *
 * @author Sudojed Team
 */
@Aspect
@Order(100)
public class LazySecurityAspect {

    private static final Logger log = LoggerFactory.getLogger(
        LazySecurityAspect.class
    );

    private final ExpressionParser expressionParser =
        new SpelExpressionParser();

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
        // Get merged security requirements from class and method level
        MergedSecurityRequirements requirements = getMergedSecurityRequirements(
            joinPoint
        );

        if (requirements == null) {
            return;
        }

        LazyUser user = LazySecurityContext.getCurrentUser();

        // Verify authentication
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }

        // Verify roles (merged from class and method)
        if (!requirements.roles.isEmpty()) {
            boolean hasRole = requirements.allRolesRequired
                ? user.hasAllRoles(requirements.roles.toArray(new String[0]))
                : user.hasAnyRole(requirements.roles.toArray(new String[0]));

            if (!hasRole) {
                log.debug(
                    "Access denied for user {} - required roles: {}, user roles: {}",
                    user.getUsername(),
                    requirements.roles,
                    user.getRoles()
                );
                throw new AccessDeniedException(requirements.message);
            }
        }

        // Verify permissions (merged from class and method)
        if (!requirements.permissions.isEmpty()) {
            boolean hasPermission = requirements.permissions
                .stream()
                .anyMatch(user::hasPermission);

            if (!hasPermission) {
                log.debug(
                    "Access denied for user {} - required permissions: {}",
                    user.getUsername(),
                    requirements.permissions
                );
                throw new AccessDeniedException(requirements.message);
            }
        }

        // Evaluate SpEL condition if present
        if (
            requirements.condition != null && !requirements.condition.isEmpty()
        ) {
            boolean conditionResult = evaluateCondition(
                requirements.condition,
                joinPoint,
                user
            );
            if (!conditionResult) {
                log.debug(
                    "Access denied for user {} - SpEL condition failed: {}",
                    user.getUsername(),
                    requirements.condition
                );
                throw new AccessDeniedException(requirements.message);
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
     * Container for merged security requirements from class and method level annotations.
     */
    private static class MergedSecurityRequirements {

        Set<String> roles = new HashSet<>();
        Set<String> permissions = new HashSet<>();
        boolean allRolesRequired = false;
        String condition = "";
        String message = "Access denied";
    }

    /**
     * Gets merged security requirements from class-level and method-level @Secured annotations.
     * Method-level annotations take precedence for individual attributes when specified,
     * but roles and permissions are combined (additive).
     *
     * @param joinPoint The join point
     * @return Merged security requirements, or null if no @Secured annotation found
     */
    private MergedSecurityRequirements getMergedSecurityRequirements(
        JoinPoint joinPoint
    ) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Class<?> targetClass = joinPoint.getTarget().getClass();

        // Get annotations from method and class
        Secured methodAnnotation = AnnotationUtils.findAnnotation(
            method,
            Secured.class
        );
        Secured classAnnotation = AnnotationUtils.findAnnotation(
            targetClass,
            Secured.class
        );

        if (methodAnnotation == null && classAnnotation == null) {
            return null;
        }

        MergedSecurityRequirements requirements =
            new MergedSecurityRequirements();

        // Merge class-level requirements first
        if (classAnnotation != null) {
            addRolesToSet(requirements.roles, classAnnotation.value());
            addRolesToSet(requirements.roles, classAnnotation.roles());
            addRolesToSet(
                requirements.permissions,
                classAnnotation.permissions()
            );
            requirements.allRolesRequired = classAnnotation.all();
            if (!classAnnotation.condition().isEmpty()) {
                requirements.condition = classAnnotation.condition();
            }
            if (!"Access denied".equals(classAnnotation.message())) {
                requirements.message = classAnnotation.message();
            }
        }

        // Method-level overrides/adds to class-level
        if (methodAnnotation != null) {
            addRolesToSet(requirements.roles, methodAnnotation.value());
            addRolesToSet(requirements.roles, methodAnnotation.roles());
            addRolesToSet(
                requirements.permissions,
                methodAnnotation.permissions()
            );

            // Method-level 'all' takes precedence if explicitly set
            if (methodAnnotation.all()) {
                requirements.allRolesRequired = true;
            }

            // Method-level condition overrides class-level
            if (!methodAnnotation.condition().isEmpty()) {
                requirements.condition = methodAnnotation.condition();
            }

            // Method-level message overrides class-level
            if (!"Access denied".equals(methodAnnotation.message())) {
                requirements.message = methodAnnotation.message();
            }
        }

        return requirements;
    }

    /**
     * Helper to add roles to a set, ignoring empty values.
     */
    private void addRolesToSet(Set<String> set, String[] values) {
        if (values != null) {
            for (String value : values) {
                if (value != null && !value.isEmpty()) {
                    set.add(value);
                }
            }
        }
    }

    /**
     * Evaluates a SpEL condition expression.
     *
     * @param condition The SpEL expression to evaluate
     * @param joinPoint The join point containing method information
     * @param user The current authenticated user
     * @return true if the condition passes, false otherwise
     */
    private boolean evaluateCondition(
        String condition,
        JoinPoint joinPoint,
        LazyUser user
    ) {
        try {
            EvaluationContext context = createEvaluationContext(
                joinPoint,
                user
            );
            Expression expression = expressionParser.parseExpression(condition);
            Boolean result = expression.getValue(context, Boolean.class);
            return result != null && result;
        } catch (Exception e) {
            log.warn(
                "Failed to evaluate SpEL condition '{}': {}",
                condition,
                e.getMessage()
            );
            return false;
        }
    }

    /**
     * Creates a SpEL evaluation context with all available variables.
     *
     * @param joinPoint The join point containing method information
     * @param user The current authenticated user
     * @return The evaluation context with all variables set
     */
    private EvaluationContext createEvaluationContext(
        JoinPoint joinPoint,
        LazyUser user
    ) {
        StandardEvaluationContext context = new StandardEvaluationContext();

        // Add principal (current user)
        context.setVariable("principal", user);
        context.setVariable("user", user);
        context.setVariable("authentication", user);

        // Add method parameters by name
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] parameterNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();

        if (parameterNames != null) {
            for (int i = 0; i < parameterNames.length; i++) {
                context.setVariable(parameterNames[i], args[i]);
            }
        }

        // Add target object
        context.setVariable("target", joinPoint.getTarget());
        context.setVariable("this", joinPoint.getTarget());

        // Add method information
        context.setVariable("method", signature.getMethod());
        context.setVariable("methodName", signature.getName());

        // Set root object as the user for convenient access
        context.setRootObject(user);

        return context;
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

        String currentUserId = user.getId();

        // Check path variable / request param ownership (field attribute)
        String field = annotation.field();
        if (field != null && !field.isEmpty()) {
            Object resourceOwnerId = extractFieldValue(joinPoint, field);

            if (resourceOwnerId == null) {
                if (!annotation.allowNullOwner()) {
                    throw new AccessDeniedException(
                        "Could not determine resource owner"
                    );
                }
            } else if (!String.valueOf(resourceOwnerId).equals(currentUserId)) {
                log.debug(
                    "Ownership check failed (field) - user: {}, resource owner: {}",
                    currentUserId,
                    resourceOwnerId
                );
                throw new AccessDeniedException(annotation.message());
            }
        }

        // Check request body ownership (requestField attribute)
        String requestField = annotation.requestField();
        if (requestField != null && !requestField.isEmpty()) {
            Object requestBody = extractRequestBody(joinPoint);
            if (requestBody != null) {
                Object requestOwnerId = extractFieldFromObject(
                    requestBody,
                    requestField
                );

                if (requestOwnerId == null) {
                    if (!annotation.allowNullOwner()) {
                        throw new AccessDeniedException(
                            "Could not determine owner from request body"
                        );
                    }
                } else if (
                    !String.valueOf(requestOwnerId).equals(currentUserId)
                ) {
                    log.debug(
                        "Ownership check failed (requestField) - user: {}, request owner: {}",
                        currentUserId,
                        requestOwnerId
                    );
                    throw new AccessDeniedException(annotation.message());
                }
            }
        }

        log.debug(
            "Ownership check passed - user: {} is owner of resource",
            currentUserId
        );
    }

    /**
     * Extracts the request body from method arguments.
     */
    private Object extractRequestBody(JoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = signature.getMethod().getParameters();

        for (int i = 0; i < parameters.length; i++) {
            // Check for @RequestBody annotation
            try {
                Class<?> requestBodyClass = Class.forName(
                    "org.springframework.web.bind.annotation.RequestBody"
                );
                if (
                    parameters[i].isAnnotationPresent(
                        (Class<? extends Annotation>) requestBodyClass
                    )
                ) {
                    return args[i];
                }
            } catch (ClassNotFoundException ignored) {}
        }

        // Fallback: return first non-primitive argument
        for (Object arg : args) {
            if (arg != null && !isPrimitiveOrWrapper(arg.getClass())) {
                return arg;
            }
        }

        return null;
    }

    /**
     * Extracts a field value from an object using reflection.
     */
    private Object extractFieldFromObject(Object obj, String fieldName) {
        if (obj == null || fieldName == null) {
            return null;
        }

        try {
            // Try getter method first
            String getterName =
                "get" +
                Character.toUpperCase(fieldName.charAt(0)) +
                fieldName.substring(1);
            try {
                Method getter = obj.getClass().getMethod(getterName);
                return getter.invoke(obj);
            } catch (NoSuchMethodException e) {
                // Try direct method with field name
                try {
                    Method method = obj.getClass().getMethod(fieldName);
                    return method.invoke(obj);
                } catch (NoSuchMethodException e2) {
                    // Try field access
                    java.lang.reflect.Field field = obj
                        .getClass()
                        .getDeclaredField(fieldName);
                    field.setAccessible(true);
                    return field.get(obj);
                }
            }
        } catch (Exception e) {
            log.trace(
                "Could not extract field '{}' from {}: {}",
                fieldName,
                obj.getClass().getSimpleName(),
                e.getMessage()
            );
            return null;
        }
    }

    /**
     * Checks if a class is a primitive or wrapper type.
     */
    private boolean isPrimitiveOrWrapper(Class<?> clazz) {
        return (
            clazz.isPrimitive() ||
            clazz == Boolean.class ||
            clazz == Byte.class ||
            clazz == Character.class ||
            clazz == Short.class ||
            clazz == Integer.class ||
            clazz == Long.class ||
            clazz == Float.class ||
            clazz == Double.class ||
            clazz == String.class
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
