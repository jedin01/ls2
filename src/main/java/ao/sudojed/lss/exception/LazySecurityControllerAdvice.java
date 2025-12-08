package ao.sudojed.lss.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

/**
 * Controller Advice para tratar exceções LSS lançadas pelos aspectos.
 * Converte exceções de segurança em respostas HTTP apropriadas.
 *
 * @author Sudojed Team
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LazySecurityControllerAdvice {

    private static final Logger log = LoggerFactory.getLogger(LazySecurityControllerAdvice.class);

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<Map<String, Object>> handleUnauthorized(UnauthorizedException ex) {
        log.debug("Unauthorized access: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse(401, "UNAUTHORIZED", ex.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex) {
        log.debug("Access denied: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(errorResponse(403, "ACCESS_DENIED", ex.getMessage()));
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimitExceeded(RateLimitExceededException ex) {
        log.debug("Rate limit exceeded: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .body(errorResponse(429, "RATE_LIMIT_EXCEEDED", ex.getMessage()));
    }
    
    @ExceptionHandler(LazySecurityException.class)
    public ResponseEntity<Map<String, Object>> handleLazySecurityException(LazySecurityException ex) {
        log.debug("Security exception: {}", ex.getMessage());
        return ResponseEntity
                .status(ex.getStatus())
                .body(errorResponse(ex.getStatus().value(), ex.getErrorCode(), ex.getMessage()));
    }

    private Map<String, Object> errorResponse(int status, String code, String message) {
        return Map.of(
                "timestamp", Instant.now().toString(),
                "status", status,
                "code", code,
                "message", message
        );
    }
}
