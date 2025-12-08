package ao.sudojed.lss.demo.dto;

/**
 * DTO para requisição de registro.
 */
public record RegisterRequest(
    String username,
    String email,
    String password
) {}
