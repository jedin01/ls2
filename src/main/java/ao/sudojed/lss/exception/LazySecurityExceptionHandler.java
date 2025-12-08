package ao.sudojed.lss.exception;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Handler unificado para erros de segurança do LazySpringSecurity.
 * Produz respostas JSON consistentes para erros de autenticação e autorização.
 *
 * @author Sudojed Team
 */
public class LazySecurityExceptionHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    private static final Logger log = LoggerFactory.getLogger(LazySecurityExceptionHandler.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        log.debug("Authentication failed for request: {} - {}", request.getMethod(), request.getRequestURI());
        sendErrorResponse(response, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", 
                "Authentication required", request.getRequestURI());
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        log.debug("Access denied for request: {} - {}", request.getMethod(), request.getRequestURI());
        sendErrorResponse(response, HttpStatus.FORBIDDEN, "ACCESS_DENIED",
                "Access denied", request.getRequestURI());
    }

    /**
     * Trata exceções do LazySpringSecurity.
     */
    public void handleLazyException(HttpServletRequest request, HttpServletResponse response,
                                    LazySecurityException exception) throws IOException {
        log.debug("Security exception for request: {} - {} - {}", 
                request.getMethod(), request.getRequestURI(), exception.getMessage());
        
        sendErrorResponse(response, exception.getStatus(), exception.getErrorCode(),
                exception.getMessage(), request.getRequestURI());
    }

    private void sendErrorResponse(HttpServletResponse response, HttpStatus status,
                                   String errorCode, String message, String path) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("code", errorCode);
        body.put("message", message);
        body.put("path", path);

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
