package ao.sudojed.lss.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Utilitário para hash de senhas.
 * Usa BCrypt por padrão (recomendado pelo OWASP).
 *
 * @author Sudojed Team
 */
public final class PasswordUtils {

    private static final PasswordEncoder encoder = new BCryptPasswordEncoder();

    private PasswordUtils() {
        // Utility class
    }

    /**
     * Gera hash da senha usando BCrypt.
     */
    public static String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    /**
     * Verifica se senha corresponde ao hash.
     */
    public static boolean matches(String rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }

    /**
     * Retorna o PasswordEncoder para uso com Spring Security.
     */
    public static PasswordEncoder encoder() {
        return encoder;
    }
}
