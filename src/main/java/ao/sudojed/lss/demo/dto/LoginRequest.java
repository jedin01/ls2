package ao.sudojed.lss.demo.dto;

/**
 * DTO para requisição de login.
 */
public record LoginRequest(
    String username,
    String password
) {}
