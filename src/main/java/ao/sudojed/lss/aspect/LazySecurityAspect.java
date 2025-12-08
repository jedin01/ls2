package ao.sudojed.lss.aspect;

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

import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.annotation.Owner;
import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.AccessDeniedException;
import ao.sudojed.lss.exception.UnauthorizedException;

/**
 * Aspect que intercepta métodos anotados com @LazySecured, @Public, @Owner, etc.
 * Executa verificações de autorização automaticamente.
 *
 * @author Sudojed Team
 */
@Aspect
@Order(100)
public class LazySecurityAspect {

    private static final Logger log = LoggerFactory.getLogger(LazySecurityAspect.class);

    /**
     * Intercepta métodos anotados com @LazySecured, @Admin, ou @Authenticated.
     * Como @Admin e @Authenticated são meta-anotados com @LazySecured,
     * precisamos interceptar explicitamente.
     */
    @Before("@annotation(ao.sudojed.lss.annotation.LazySecured) || " +
            "@within(ao.sudojed.lss.annotation.LazySecured) || " +
            "@annotation(ao.sudojed.lss.annotation.Admin) || " +
            "@within(ao.sudojed.lss.annotation.Admin) || " +
            "@annotation(ao.sudojed.lss.annotation.Authenticated) || " +
            "@within(ao.sudojed.lss.annotation.Authenticated)")
    public void checkLazySecured(JoinPoint joinPoint) {
        LazySecured annotation = getAnnotation(joinPoint, LazySecured.class);
        
        if (annotation == null) {
            return;
        }

        LazyUser user = LazySecurityContext.getCurrentUser();

        // Verifica autenticação
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }

        // Verifica roles
        String[] roles = annotation.roles();
        if (roles.length > 0) {
            boolean hasRole = switch (annotation.logic()) {
                case ANY -> user.hasAnyRole(roles);
                case ALL -> user.hasAllRoles(roles);
            };

            if (!hasRole) {
                log.debug("Access denied for user {} - required roles: {}, user roles: {}",
                        user.getUsername(), Arrays.toString(roles), user.getRoles());
                throw new AccessDeniedException(annotation.message());
            }
        }

        // Verifica permissões
        String[] permissions = annotation.permissions();
        if (permissions.length > 0) {
            boolean hasPermission = Arrays.stream(permissions)
                    .anyMatch(user::hasPermission);

            if (!hasPermission) {
                log.debug("Access denied for user {} - required permissions: {}",
                        user.getUsername(), Arrays.toString(permissions));
                throw new AccessDeniedException(annotation.message());
            }
        }

        log.debug("Access granted for user {} to {}.{}",
                user.getUsername(), joinPoint.getTarget().getClass().getSimpleName(),
                joinPoint.getSignature().getName());
    }

    /**
     * Intercepta métodos anotados com @Owner.
     */
    @Before("@annotation(ao.sudojed.lss.annotation.Owner)")
    public void checkOwnership(JoinPoint joinPoint) {
        Owner annotation = getAnnotation(joinPoint, Owner.class);
        
        if (annotation == null) {
            return;
        }

        LazyUser user = LazySecurityContext.getCurrentUser();

        // Verifica autenticação
        if (!user.isAuthenticated()) {
            throw new UnauthorizedException("Authentication required");
        }

        // Admin bypass
        if (annotation.adminBypass() && user.isAdmin()) {
            log.debug("Admin bypass for ownership check - user: {}", user.getUsername());
            return;
        }

        // Bypass por roles específicas
        for (String role : annotation.bypassRoles()) {
            if (user.hasRole(role)) {
                log.debug("Role bypass for ownership check - user: {}, role: {}", 
                        user.getUsername(), role);
                return;
            }
        }

        // Extrai o valor do campo de ownership dos argumentos
        Object resourceOwnerId = extractFieldValue(joinPoint, annotation.field());
        String currentUserId = user.getId();

        if (resourceOwnerId == null) {
            throw new AccessDeniedException("Could not determine resource owner");
        }

        if (!String.valueOf(resourceOwnerId).equals(currentUserId)) {
            log.debug("Ownership check failed - user: {}, resource owner: {}",
                    currentUserId, resourceOwnerId);
            throw new AccessDeniedException(annotation.message());
        }

        log.debug("Ownership check passed - user: {} is owner of resource", currentUserId);
    }

    /**
     * Métodos @Public não precisam de verificação (bypass).
     */
    @Before("@annotation(ao.sudojed.lss.annotation.Public) || @within(ao.sudojed.lss.annotation.Public)")
    public void handlePublic(JoinPoint joinPoint) {
        // Não faz nada - apenas garante que o método não seja bloqueado
        log.debug("Public access granted to {}.{}",
                joinPoint.getTarget().getClass().getSimpleName(),
                joinPoint.getSignature().getName());
    }

    /**
     * Extrai anotação do método ou da classe.
     */
    @SuppressWarnings("unchecked")
    private <T extends Annotation> T getAnnotation(JoinPoint joinPoint, Class<T> annotationType) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Primeiro tenta no método
        T annotation = AnnotationUtils.findAnnotation(method, annotationType);
        if (annotation != null) {
            return annotation;
        }

        // Depois tenta na classe
        return AnnotationUtils.findAnnotation(joinPoint.getTarget().getClass(), annotationType);
    }

    /**
     * Extrai valor de um campo dos argumentos do método.
     */
    private Object extractFieldValue(JoinPoint joinPoint, String fieldName) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] parameterNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();

        // Procura por nome do parâmetro
        for (int i = 0; i < parameterNames.length; i++) {
            if (parameterNames[i].equals(fieldName)) {
                return args[i];
            }
        }

        // Procura em anotações @PathVariable, @RequestParam, etc.
        Method method = signature.getMethod();
        Parameter[] parameters = method.getParameters();
        
        for (int i = 0; i < parameters.length; i++) {
            // Verifica se o nome do parâmetro da anotação corresponde
            if (hasMatchingAnnotation(parameters[i], fieldName)) {
                return args[i];
            }
        }

        return null;
    }

    private boolean hasMatchingAnnotation(Parameter parameter, String fieldName) {
        // Verifica @PathVariable
        try {
            Class<?> pathVariableClass = Class.forName("org.springframework.web.bind.annotation.PathVariable");
            Annotation pathVariable = parameter.getAnnotation((Class<? extends Annotation>) pathVariableClass);
            if (pathVariable != null) {
                String value = (String) pathVariableClass.getMethod("value").invoke(pathVariable);
                String name = (String) pathVariableClass.getMethod("name").invoke(pathVariable);
                if (fieldName.equals(value) || fieldName.equals(name)) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }

        // Verifica @RequestParam
        try {
            Class<?> requestParamClass = Class.forName("org.springframework.web.bind.annotation.RequestParam");
            Annotation requestParam = parameter.getAnnotation((Class<? extends Annotation>) requestParamClass);
            if (requestParam != null) {
                String value = (String) requestParamClass.getMethod("value").invoke(requestParam);
                String name = (String) requestParamClass.getMethod("name").invoke(requestParam);
                if (fieldName.equals(value) || fieldName.equals(name)) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }

        return false;
    }
}
