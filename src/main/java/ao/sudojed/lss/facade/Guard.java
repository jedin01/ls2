package ao.sudojed.lss.facade;

import ao.sudojed.lss.exception.AccessDeniedException;

/**
 * Classe utilitaria para verificacao de autorizacao.
 * Fornece metodos estaticos para verificar permissoes de forma declarativa.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * // Verificar role
 * Guard.role("ADMIN");  // lanca excecao se nao for admin
 * 
 * // Verificar qualquer role
 * Guard.anyRole("ADMIN", "MANAGER");
 * 
 * // Verificar se eh dono do recurso
 * Guard.owner(resourceOwnerId);
 * 
 * // Verificar condicao customizada
 * Guard.when(user.isActive(), "Usuario inativo");
 * }</pre>
 * 
 * @author Sudojed Team
 */
public final class Guard {

    private Guard() {
        // Classe utilitaria
    }

    // ========================================================================
    // VERIFICACAO DE ROLES
    // ========================================================================

    /**
     * Exige que o usuario tenha a role especificada.
     * 
     * @param role role requerida
     * @throws AccessDeniedException se nao possui a role
     */
    public static void role(String role) {
        Auth.requireAuth();
        if (!Auth.hasRole(role)) {
            throw new AccessDeniedException("Acesso negado. Role requerida: " + role);
        }
    }

    /**
     * Exige que o usuario tenha pelo menos uma das roles.
     * 
     * @param roles roles aceitas
     * @throws AccessDeniedException se nao possui nenhuma
     */
    public static void anyRole(String... roles) {
        Auth.requireAuth();
        if (!Auth.hasAnyRole(roles)) {
            throw new AccessDeniedException(
                "Acesso negado. Requer uma das roles: " + String.join(", ", roles));
        }
    }

    /**
     * Exige que o usuario tenha todas as roles especificadas.
     * 
     * @param roles roles requeridas
     * @throws AccessDeniedException se nao possui todas
     */
    public static void allRoles(String... roles) {
        Auth.requireAuth();
        if (!Auth.hasAllRoles(roles)) {
            throw new AccessDeniedException(
                "Acesso negado. Requer todas as roles: " + String.join(", ", roles));
        }
    }

    /**
     * Exige que o usuario seja admin.
     * 
     * @throws AccessDeniedException se nao for admin
     */
    public static void admin() {
        role("ADMIN");
    }

    // ========================================================================
    // VERIFICACAO DE PROPRIEDADE (OWNER)
    // ========================================================================

    /**
     * Verifica se o usuario atual eh o dono do recurso.
     * Admin tem bypass automatico.
     * 
     * @param resourceOwnerId ID do dono do recurso
     * @throws AccessDeniedException se nao for dono nem admin
     */
    public static void owner(String resourceOwnerId) {
        Auth.requireAuth();
        
        String currentUserId = Auth.id();
        
        // Admin pode acessar qualquer recurso
        if (Auth.isAdmin()) {
            return;
        }
        
        if (!currentUserId.equals(resourceOwnerId)) {
            throw new AccessDeniedException(
                "Acesso negado. Voce nao eh o proprietario deste recurso.");
        }
    }

    /**
     * Verifica se o usuario atual eh o dono OU tem uma role especifica.
     * 
     * @param resourceOwnerId ID do dono do recurso
     * @param bypassRole role que permite bypass
     * @throws AccessDeniedException se nao for dono nem tiver a role
     */
    public static void ownerOr(String resourceOwnerId, String bypassRole) {
        Auth.requireAuth();
        
        if (Auth.hasRole(bypassRole)) {
            return;
        }
        
        if (!Auth.id().equals(resourceOwnerId)) {
            throw new AccessDeniedException(
                "Acesso negado. Requer ser proprietario ou ter role: " + bypassRole);
        }
    }

    // ========================================================================
    // VERIFICACOES CONDICIONAIS
    // ========================================================================

    /**
     * Exige que uma condicao seja verdadeira.
     * 
     * @param condition condicao a verificar
     * @param message mensagem de erro se falhar
     * @throws AccessDeniedException se condicao for falsa
     */
    public static void when(boolean condition, String message) {
        if (!condition) {
            throw new AccessDeniedException(message);
        }
    }

    /**
     * Exige que uma condicao seja verdadeira.
     * 
     * @param condition condicao a verificar
     * @throws AccessDeniedException se condicao for falsa
     */
    public static void when(boolean condition) {
        when(condition, "Acesso negado");
    }

    /**
     * Exige autenticacao.
     * 
     * @throws ao.sudojed.lss.exception.UnauthorizedException se nao autenticado
     */
    public static void authenticated() {
        Auth.requireAuth();
    }

    /**
     * Permite apenas guests (nao autenticados).
     * Util para paginas de login/registro.
     * 
     * @throws AccessDeniedException se ja estiver autenticado
     */
    public static void guest() {
        if (Auth.check()) {
            throw new AccessDeniedException("Acao disponivel apenas para visitantes");
        }
    }

    // ========================================================================
    // VERIFICACOES COMPOSTAS
    // ========================================================================

    /**
     * Inicia uma verificacao fluente.
     * 
     * @return builder para verificacao fluente
     */
    public static GuardChain check() {
        return new GuardChain();
    }

    /**
     * Builder para verificacoes fluentes.
     */
    public static class GuardChain {
        private boolean passed = true;
        private String failMessage = "Acesso negado";

        /**
         * Adiciona verificacao de role.
         */
        public GuardChain role(String role) {
            if (passed && !Auth.hasRole(role)) {
                passed = false;
                failMessage = "Role requerida: " + role;
            }
            return this;
        }

        /**
         * Adiciona verificacao de propriedade.
         */
        public GuardChain owner(String resourceOwnerId) {
            if (passed && !Auth.isAdmin() && !Auth.id().equals(resourceOwnerId)) {
                passed = false;
                failMessage = "Nao eh proprietario do recurso";
            }
            return this;
        }

        /**
         * Adiciona verificacao customizada.
         */
        public GuardChain when(boolean condition, String message) {
            if (passed && !condition) {
                passed = false;
                failMessage = message;
            }
            return this;
        }

        /**
         * Permite passar se qualquer verificacao anterior passou.
         * Reseta o estado para tentar alternativa.
         */
        public GuardChain or() {
            if (passed) {
                return this; // Ja passou, ignora resto
            }
            passed = true; // Reseta para tentar alternativa
            return this;
        }

        /**
         * Finaliza e lanca excecao se nenhuma verificacao passou.
         * 
         * @throws AccessDeniedException se todas verificacoes falharam
         */
        public void authorize() {
            if (!passed) {
                throw new AccessDeniedException(failMessage);
            }
        }
    }
}
