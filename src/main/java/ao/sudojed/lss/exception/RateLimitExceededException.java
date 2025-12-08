package ao.sudojed.lss.exception;

import org.springframework.http.HttpStatus;

/**
 * Exceção lançada quando rate limit é excedido (429 Too Many Requests).
 *
 * @author Sudojed Team
 */
public class RateLimitExceededException extends LazySecurityException {

    private final long retryAfterSeconds;

    public RateLimitExceededException() {
        this("Rate limit exceeded. Please try again later.", 60);
    }

    public RateLimitExceededException(String message, long retryAfterSeconds) {
        super(message, HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
