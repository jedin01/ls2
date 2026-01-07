package ao.sudojed.lss.aspect;

import ao.sudojed.lss.annotation.Audit;
import ao.sudojed.lss.annotation.Audit.AuditLevel;
import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Aspect that intercepts methods annotated with @Audit and logs security events.
 *
 * @author Sudojed Team
 * @since 1.1.0
 */
@Aspect
@Order(50)
public class AuditAspect {

    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");
    private static final Logger log = LoggerFactory.getLogger(AuditAspect.class);

    /**
     * Intercepts methods annotated with @Audit.
     */
    @Around("@annotation(audit)")
    public Object auditMethod(ProceedingJoinPoint joinPoint, Audit audit) throws Throwable {
        long startTime = System.currentTimeMillis();
        String action = determineAction(joinPoint, audit);
        LazyUser user = LazySecurityContext.getCurrentUser();

        AuditEvent event = new AuditEvent();
        event.timestamp = Instant.now().toString();
        event.action = action;
        event.category = audit.category();
        event.level = audit.level();
        event.userId = user.isAuthenticated() ? user.getId() : "anonymous";
        event.username = user.isAuthenticated() ? user.getUsername() : "anonymous";
        event.roles = user.isAuthenticated() ? String.join(",", user.getRoles()) : "";
        event.className = joinPoint.getTarget().getClass().getSimpleName();
        event.methodName = getMethodName(joinPoint);
        event.clientIp = getClientIp();

        if (audit.includeParams()) {
            event.parameters = extractParameters(joinPoint, audit.excludeParams());
        }

        Object result = null;
        Throwable exception = null;

        try {
            result = joinPoint.proceed();
            event.success = true;
            event.duration = System.currentTimeMillis() - startTime;

            if (audit.includeResponse() && result != null) {
                event.response = truncateResponse(result.toString());
            }

            return result;
        } catch (Throwable t) {
            exception = t;
            event.success = false;
            event.duration = System.currentTimeMillis() - startTime;
            event.errorMessage = t.getMessage();
            event.errorType = t.getClass().getSimpleName();
            throw t;
        } finally {
            if (!audit.onlyOnSuccess() || event.success) {
                logAuditEvent(event, audit);
            }
        }
    }

    /**
     * Determines the action name for the audit log.
     */
    private String determineAction(ProceedingJoinPoint joinPoint, Audit audit) {
        if (audit.action() != null && !audit.action().isEmpty()) {
            return audit.action();
        }

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        String methodName = signature.getName();

        return className + "." + methodName;
    }

    /**
     * Gets the method name from the join point.
     */
    private String getMethodName(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        return signature.getName();
    }

    /**
     * Extracts method parameters, excluding sensitive ones.
     */
    private Map<String, String> extractParameters(ProceedingJoinPoint joinPoint, String[] excludeParams) {
        Map<String, String> params = new LinkedHashMap<>();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();
        Set<String> excluded = Set.of(excludeParams);

        if (paramNames != null) {
            for (int i = 0; i < paramNames.length; i++) {
                String paramName = paramNames[i];
                if (!excluded.contains(paramName) && !isSensitiveParam(paramName)) {
                    Object value = args[i];
                    params.put(paramName, value != null ? truncateValue(value.toString()) : "null");
                } else {
                    params.put(paramName, "[REDACTED]");
                }
            }
        }

        return params;
    }

    /**
     * Checks if a parameter name suggests sensitive data.
     */
    private boolean isSensitiveParam(String paramName) {
        String lower = paramName.toLowerCase();
        return lower.contains("password") ||
               lower.contains("secret") ||
               lower.contains("token") ||
               lower.contains("key") ||
               lower.contains("credential") ||
               lower.contains("credit") ||
               lower.contains("cvv") ||
               lower.contains("ssn");
    }

    /**
     * Gets the client IP address from the current request.
     */
    private String getClientIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes();
            if (attrs != null && attrs.getRequest() != null) {
                String xForwardedFor = attrs.getRequest().getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    return xForwardedFor.split(",")[0].trim();
                }
                return attrs.getRequest().getRemoteAddr();
            }
        } catch (Exception e) {
            log.trace("Could not get client IP: {}", e.getMessage());
        }
        return "unknown";
    }

    /**
     * Truncates a value to prevent extremely long log entries.
     */
    private String truncateValue(String value) {
        if (value == null) return "null";
        if (value.length() > 200) {
            return value.substring(0, 200) + "...[truncated]";
        }
        return value;
    }

    /**
     * Truncates a response to prevent extremely long log entries.
     */
    private String truncateResponse(String response) {
        if (response == null) return "null";
        if (response.length() > 500) {
            return response.substring(0, 500) + "...[truncated]";
        }
        return response;
    }

    /**
     * Logs the audit event.
     */
    private void logAuditEvent(AuditEvent event, Audit audit) {
        String message = formatAuditMessage(event, audit);

        switch (event.level) {
            case LOW:
                auditLog.debug(message);
                break;
            case NORMAL:
                auditLog.info(message);
                break;
            case HIGH:
                auditLog.info(message);
                break;
            case SENSITIVE:
                auditLog.warn(message);
                break;
            case CRITICAL:
                auditLog.warn(message);
                break;
            default:
                auditLog.info(message);
        }
    }

    /**
     * Formats the audit message.
     */
    private String formatAuditMessage(AuditEvent event, Audit audit) {
        StringBuilder sb = new StringBuilder();

        // Use custom message template if provided
        if (audit.message() != null && !audit.message().isEmpty()) {
            String msg = audit.message()
                .replace("{user}", event.username)
                .replace("{action}", event.action)
                .replace("{method}", event.methodName)
                .replace("{class}", event.className)
                .replace("{ip}", event.clientIp)
                .replace("{timestamp}", event.timestamp);
            sb.append(msg);
        } else {
            // Default format
            sb.append("[AUDIT] ");
            sb.append(event.level.name()).append(" | ");
            sb.append(event.category).append(" | ");
            sb.append(event.action).append(" | ");
            sb.append("user=").append(event.username);
            sb.append(" (").append(event.userId).append(") | ");
            sb.append("ip=").append(event.clientIp).append(" | ");
            sb.append("success=").append(event.success).append(" | ");
            sb.append("duration=").append(event.duration).append("ms");
        }

        if (event.parameters != null && !event.parameters.isEmpty()) {
            sb.append(" | params=").append(event.parameters);
        }

        if (event.response != null) {
            sb.append(" | response=").append(event.response);
        }

        if (!event.success && event.errorMessage != null) {
            sb.append(" | error=").append(event.errorType)
              .append(": ").append(event.errorMessage);
        }

        return sb.toString();
    }

    /**
     * Container for audit event data.
     */
    private static class AuditEvent {
        String timestamp;
        String action;
        String category;
        AuditLevel level;
        String userId;
        String username;
        String roles;
        String className;
        String methodName;
        String clientIp;
        Map<String, String> parameters;
        String response;
        boolean success;
        long duration;
        String errorMessage;
        String errorType;
    }
}
