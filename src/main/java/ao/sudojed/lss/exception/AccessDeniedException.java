package ao.sudojed.lss.exception;

import org.springframework.http.HttpStatus;

/**
 * Exceção lançada quando acesso é negado (403 Forbidden).
 *
 * @author Sudojed Team
 */
public class AccessDeniedException extends LazySecurityException {

    public AccessDeniedException() {
        this("Access denied");
    }

    public AccessDeniedException(String message) {
        super(message, HttpStatus.FORBIDDEN, "ACCESS_DENIED");
    }

    public AccessDeniedException(String message, Throwable cause) {
        super(message, HttpStatus.FORBIDDEN, "ACCESS_DENIED", cause);
    }
}
