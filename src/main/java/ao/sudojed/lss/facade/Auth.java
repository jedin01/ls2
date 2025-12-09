package ao.sudojed.lss.facade;

import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.exception.UnauthorizedException;
import ao.sudojed.lss.util.PasswordUtils;

import java.util.Optional;
import java.util.function.Function;

/**
 * Facade de autenticacao estilo Laravel.
 * 
 * Permite acesso estatico a operacoes de autenticacao em qualquer
 * parte do codigo, sem necessidade de injecao de dependencias.
 * 
 * <h2>Uso Basico</h2>
 * <pre>{@code
 * // Verificar se esta autenticado
 * if (Auth.check()) { ... }
 * 
 * // Obter usuario atual
 * LazyUser user = Auth.user();
 * 
 * // Verificar roles
 * if (Auth.hasRole("ADMIN")) { ... }
 * 
 * // Obter ID do usuario
 * String id = Auth.id();
 * 
 * // Executar acao apenas se autenticado
 * Auth.ifAuthenticated(user -> {
 *     System.out.println("Ola, " + user.getUsername());
 * });
 * }</pre>
 * 
 * <h2>Comparacao com Laravel</h2>
 * <table>
 *   <tr><th>Laravel</th><th>LSS</th></tr>
 *   <tr><td>Auth::check()</td><td>Auth.check()</td></tr>
 *   <tr><td>Auth::user()</td><td>Auth.user()</td></tr>
 *   <tr><td>Auth::id()</td><td>Auth.id()</td></tr>
 *   <tr><td>Auth::guest()</td><td>Auth.guest()</td></tr>
 * </table>
 * 
 * @author Sudojed Team
 * @see LazySecurityContext
 * @see LazyUser
 */
public final class Auth {

    // Provider de autenticacao (para operacoes de login)
    private static AuthProvider provider;

    private Auth() {
        // Classe utilitaria - nao instanciar
    }

    // ========================================================================
    // VERIFICACAO DE AUTENTICACAO
    // ========================================================================

    /**
     * Verifica se ha um usuario autenticado.
     * Equivalente ao Auth::check() do Laravel.
     * 
     * @return true se autenticado
     */
    public static boolean check() {
        return LazySecurityContext.isAuthenticated();
    }

    /**
     * Verifica se o usuario eh um visitante (nao autenticado).
     * Equivalente ao Auth::guest() do Laravel.
     * 
     * @return true se NAO autenticado
     */
    public static boolean guest() {
        return !check();
    }

    // ========================================================================
    // ACESSO AO USUARIO
    // ========================================================================

    /**
     * Obtem o usuario autenticado atual.
     * Equivalente ao Auth::user() do Laravel.
     * 
     * @return LazyUser atual ou usuario anonimo se nao autenticado
     */
    public static LazyUser user() {
        return LazySecurityContext.getCurrentUser();
    }

    /**
     * Obtem o usuario como Optional (vazio se nao autenticado).
     * 
     * @return Optional com usuario ou empty
     */
    public static Optional<LazyUser> userOptional() {
        return LazySecurityContext.getUser();
    }

    /**
     * Obtem o ID do usuario autenticado.
     * Equivalente ao Auth::id() do Laravel.
     * 
     * @return ID do usuario ou null se nao autenticado
     */
    public static String id() {
        return check() ? user().getId() : null;
    }

    /**
     * Obtem o username do usuario autenticado.
     * 
     * @return username ou null se nao autenticado
     */
    public static String username() {
        return check() ? user().getUsername() : null;
    }

    // ========================================================================
    // VERIFICACAO DE ROLES E PERMISSOES
    // ========================================================================

    /**
     * Verifica se o usuario tem uma role especifica.
     * 
     * @param role nome da role (ex: "ADMIN", "MANAGER")
     * @return true se possui a role
     */
    public static boolean hasRole(String role) {
        return LazySecurityContext.hasRole(role);
    }

    /**
     * Verifica se o usuario tem qualquer uma das roles.
     * 
     * @param roles array de roles
     * @return true se possui pelo menos uma
     */
    public static boolean hasAnyRole(String... roles) {
        return LazySecurityContext.hasAnyRole(roles);
    }

    /**
     * Verifica se o usuario tem todas as roles especificadas.
     * 
     * @param roles array de roles
     * @return true se possui todas
     */
    public static boolean hasAllRoles(String... roles) {
        return LazySecurityContext.hasAllRoles(roles);
    }

    /**
     * Verifica se o usuario tem uma permissao especifica.
     * 
     * @param permission nome da permissao
     * @return true se possui a permissao
     */
    public static boolean can(String permission) {
        return LazySecurityContext.hasPermission(permission);
    }

    /**
     * Verifica se o usuario NAO tem uma permissao.
     * 
     * @param permission nome da permissao
     * @return true se NAO possui a permissao
     */
    public static boolean cannot(String permission) {
        return !can(permission);
    }

    /**
     * Verifica se o usuario eh admin.
     * 
     * @return true se possui role ADMIN
     */
    public static boolean isAdmin() {
        return LazySecurityContext.isAdmin();
    }

    // ========================================================================
    // AUTENTICACAO (LOGIN/LOGOUT)
    // ========================================================================

    /**
     * Tenta autenticar com credenciais.
     * 
     * @param username nome de usuario
     * @param password senha em texto plano
     * @return true se autenticado com sucesso
     */
    public static boolean attempt(String username, String password) {
        if (provider == null) {
            throw new IllegalStateException(
                "AuthProvider nao configurado. Configure via Auth.setProvider()");
        }
        return provider.attempt(username, password);
    }

    /**
     * Valida credenciais sem fazer login.
     * 
     * @param username nome de usuario
     * @param password senha em texto plano
     * @return true se credenciais validas
     */
    public static boolean validate(String username, String password) {
        if (provider == null) {
            throw new IllegalStateException(
                "AuthProvider nao configurado. Configure via Auth.setProvider()");
        }
        return provider.validate(username, password);
    }

    /**
     * Autentica um usuario diretamente (sem verificar senha).
     * Util apos registro ou recuperacao de senha.
     * 
     * @param user usuario a autenticar
     */
    public static void login(LazyUser user) {
        LazySecurityContext.setCurrentUser(user);
    }

    /**
     * Desloga o usuario atual.
     */
    public static void logout() {
        LazySecurityContext.clear();
    }

    // ========================================================================
    // UTILITARIOS
    // ========================================================================

    /**
     * Executa acao apenas se autenticado.
     * 
     * @param action acao a executar com o usuario
     */
    public static void ifAuthenticated(java.util.function.Consumer<LazyUser> action) {
        if (check()) {
            action.accept(user());
        }
    }

    /**
     * Executa acao apenas se guest.
     * 
     * @param action acao a executar
     */
    public static void ifGuest(Runnable action) {
        if (guest()) {
            action.run();
        }
    }

    /**
     * Obtem valor se autenticado, ou default se nao.
     * 
     * @param mapper funcao para extrair valor do usuario
     * @param defaultValue valor padrao
     * @return valor extraido ou default
     */
    public static <T> T getOrDefault(Function<LazyUser, T> mapper, T defaultValue) {
        return check() ? mapper.apply(user()) : defaultValue;
    }

    /**
     * Obtem claim do usuario.
     * 
     * @param key nome da claim
     * @return valor da claim ou null
     */
    public static Object claim(String key) {
        return user().getClaim(key);
    }

    /**
     * Obtem claim do usuario com tipo.
     * 
     * @param key nome da claim
     * @param defaultValue valor padrao se claim nao existir
     * @return valor da claim ou default
     */
    public static <T> T claim(String key, T defaultValue) {
        return user().getClaim(key, defaultValue);
    }

    /**
     * Exige autenticacao. Lanca excecao se nao autenticado.
     * 
     * @throws UnauthorizedException se nao autenticado
     */
    public static void requireAuth() {
        if (!check()) {
            throw new UnauthorizedException("Autenticacao requerida");
        }
    }

    /**
     * Exige uma role especifica.
     * 
     * @param role role requerida
     * @throws ao.sudojed.lss.exception.AccessDeniedException se nao possui a role
     */
    public static void requireRole(String role) {
        requireAuth();
        if (!hasRole(role)) {
            throw new ao.sudojed.lss.exception.AccessDeniedException(
                "Role requerida: " + role);
        }
    }

    /**
     * Executa como outro usuario (para testes).
     * 
     * @param user usuario a impersonar
     * @param action acao a executar
     * @return resultado da acao
     */
    public static <T> T runAs(LazyUser user, java.util.function.Supplier<T> action) {
        return LazySecurityContext.runAs(user, action);
    }

    // ========================================================================
    // CONFIGURACAO
    // ========================================================================

    /**
     * Configura o provider de autenticacao.
     * 
     * @param authProvider implementacao do provider
     */
    public static void setProvider(AuthProvider authProvider) {
        provider = authProvider;
    }

    /**
     * Interface para provider de autenticacao customizado.
     */
    @FunctionalInterface
    public interface AuthProvider {
        /**
         * Tenta autenticar com credenciais.
         * 
         * @param username nome de usuario
         * @param password senha
         * @return true se sucesso
         */
        boolean attempt(String username, String password);

        /**
         * Valida credenciais sem fazer login.
         * Por padrao, apenas chama attempt.
         */
        default boolean validate(String username, String password) {
            return attempt(username, password);
        }
    }

    // ========================================================================
    // HELPERS DE SENHA
    // ========================================================================

    /**
     * Faz hash de uma senha.
     * 
     * @param password senha em texto plano
     * @return hash da senha
     */
    public static String hashPassword(String password) {
        return PasswordUtils.hash(password);
    }

    /**
     * Verifica se senha corresponde ao hash.
     * 
     * @param password senha em texto plano
     * @param hash hash armazenado
     * @return true se corresponde
     */
    public static boolean checkPassword(String password, String hash) {
        return PasswordUtils.matches(password, hash);
    }
}
