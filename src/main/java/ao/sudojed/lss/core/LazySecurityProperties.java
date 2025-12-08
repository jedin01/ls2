package ao.sudojed.lss.core;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propriedades de configuração do LazySpringSecurity via application.yml.
 * 
 * <h2>Exemplo application.yml</h2>
 * <pre>{@code
 * lazy:
 *   security:
 *     jwt:
 *       secret: ${JWT_SECRET:my-super-secret-key-that-is-at-least-32-chars}
 *       expiration: 3600000
 *       refresh-expiration: 604800000
 *       issuer: my-app
 *     public-paths:
 *       - /api/auth/**
 *       - /api/public/**
 *       - /actuator/health
 *       - /swagger-ui/**
 *       - /v3/api-docs/**
 *     default-role: USER
 *     csrf-enabled: false
 *     cors:
 *       enabled: true
 *       origins:
 *         - http://localhost:3000
 *         - https://myapp.com
 *       methods:
 *         - GET
 *         - POST
 *         - PUT
 *         - DELETE
 *     debug: false
 * }</pre>
 *
 * @author Sudojed Team
 */
@ConfigurationProperties(prefix = "lazy.security")
public class LazySecurityProperties {

    /**
     * Configurações JWT.
     */
    private Jwt jwt = new Jwt();

    /**
     * Paths públicos sem autenticação.
     */
    private List<String> publicPaths = new ArrayList<>();

    /**
     * Role padrão para usuários autenticados.
     */
    private String defaultRole = "USER";

    /**
     * Habilita proteção CSRF.
     */
    private boolean csrfEnabled = false;

    /**
     * Configurações CORS.
     */
    private Cors cors = new Cors();

    /**
     * Modo debug para logs detalhados.
     */
    private boolean debug = false;

    /**
     * Paths que requerem HTTPS.
     */
    private List<String> securePaths = new ArrayList<>();

    // ==================== Getters/Setters ====================

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public String getDefaultRole() {
        return defaultRole;
    }

    public void setDefaultRole(String defaultRole) {
        this.defaultRole = defaultRole;
    }

    public boolean isCsrfEnabled() {
        return csrfEnabled;
    }

    public void setCsrfEnabled(boolean csrfEnabled) {
        this.csrfEnabled = csrfEnabled;
    }

    public Cors getCors() {
        return cors;
    }

    public void setCors(Cors cors) {
        this.cors = cors;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public List<String> getSecurePaths() {
        return securePaths;
    }

    public void setSecurePaths(List<String> securePaths) {
        this.securePaths = securePaths;
    }

    // ==================== Nested Classes ====================

    public static class Jwt {
        private String secret = "";
        private long expiration = 3600000L; // 1 hora
        private long refreshExpiration = 604800000L; // 7 dias
        private String header = "Authorization";
        private String prefix = "Bearer ";
        private String issuer = "lazy-spring-security";
        private String audience = "";
        private String algorithm = "HS256";

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public long getExpiration() {
            return expiration;
        }

        public void setExpiration(long expiration) {
            this.expiration = expiration;
        }

        public long getRefreshExpiration() {
            return refreshExpiration;
        }

        public void setRefreshExpiration(long refreshExpiration) {
            this.refreshExpiration = refreshExpiration;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public String getPrefix() {
            return prefix;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
    }

    public static class Cors {
        private boolean enabled = true;
        private List<String> origins = List.of("*");
        private List<String> methods = List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");
        private List<String> headers = List.of("*");
        private boolean allowCredentials = false;
        private long maxAge = 3600L;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getOrigins() {
            return origins;
        }

        public void setOrigins(List<String> origins) {
            this.origins = origins;
        }

        public List<String> getMethods() {
            return methods;
        }

        public void setMethods(List<String> methods) {
            this.methods = methods;
        }

        public List<String> getHeaders() {
            return headers;
        }

        public void setHeaders(List<String> headers) {
            this.headers = headers;
        }

        public boolean isAllowCredentials() {
            return allowCredentials;
        }

        public void setAllowCredentials(boolean allowCredentials) {
            this.allowCredentials = allowCredentials;
        }

        public long getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(long maxAge) {
            this.maxAge = maxAge;
        }
    }
}
