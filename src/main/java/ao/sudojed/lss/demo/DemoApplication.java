package ao.sudojed.lss.demo;

import ao.sudojed.lss.annotation.EnableLazySecurity;
import ao.sudojed.lss.annotation.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Aplicacao de demonstracao do LazySpringSecurity (LSS)
 * 
 * Esta aplicacao demonstra como usar o LSS para implementar
 * autenticacao e autorizacao de forma simples e elegante.
 * 
 * Execute: ./mvnw spring-boot:run -Dspring-boot.run.main-class=ao.sudojed.lss.demo.DemoApplication
 * 
 * Endpoints disponiveis:
 * 
 * PUBLICOS (sem autenticacao):
 *   POST /auth/register     - Registrar novo usuario
 *   POST /auth/login        - Login e obter token JWT
 *   GET  /auth/health       - Health check
 * 
 * PROTEGIDOS (requer autenticacao):
 *   GET  /api/profile       - Ver perfil do usuario logado
 *   PUT  /api/profile       - Atualizar perfil
 *   GET  /api/orders        - Listar pedidos do usuario
 * 
 * ADMIN ONLY:
 *   GET  /api/admin/users   - Listar todos usuarios
 *   DELETE /api/admin/users/{id} - Deletar usuario
 * 
 * OWNER (apenas dono do recurso ou admin):
 *   GET  /api/users/{userId}/settings - Ver configuracoes do usuario
 */
@SpringBootApplication(scanBasePackages = "ao.sudojed.lss.demo")
@EnableLazySecurity(
    publicPaths = {"/auth/**", "/error"},
    jwt = @JwtConfig(
        secret = "${JWT_SECRET:minha-chave-secreta-super-segura-para-demo-lss-2024}",
        expiration = 3600,           // 1 hora
        refreshExpiration = 604800,  // 7 dias
        issuer = "lss-demo"
    ),
    corsEnabled = true,
    corsOrigins = {"http://localhost:3000", "http://localhost:5173"},
    debug = true
)
public class DemoApplication {

    public static void main(String[] args) {
        System.out.println("""
            
            ================================================================
                   LazySpringSecurity Demo Application
            ================================================================
            
              Endpoints disponiveis:
            
              PUBLICOS:
                 POST /auth/register  - Registrar usuario
                 POST /auth/login     - Login
                 GET  /auth/health    - Health check
            
              AUTENTICADOS:
                 GET  /api/profile    - Ver perfil
                 GET  /api/orders     - Listar pedidos
            
              ADMIN:
                 GET  /api/admin/users - Listar usuarios
            
            ================================================================
            """);
        
        SpringApplication.run(DemoApplication.class, args);
    }
}
