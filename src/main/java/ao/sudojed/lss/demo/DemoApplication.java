package ao.sudojed.lss.demo;

import ao.sudojed.lss.annotation.EnableLazySecurity;
import ao.sudojed.lss.annotation.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 🚀 Aplicação de demonstração do LazySpringSecurity (LSS)
 * 
 * Esta aplicação demonstra como usar o LSS para implementar
 * autenticação e autorização de forma simples e elegante.
 * 
 * Execute: ./mvnw spring-boot:run -Dspring-boot.run.main-class=ao.sudojed.lss.demo.DemoApplication
 * 
 * Endpoints disponíveis:
 * 
 * 📢 PÚBLICOS (sem autenticação):
 *   POST /auth/register     - Registrar novo usuário
 *   POST /auth/login        - Login e obter token JWT
 *   GET  /auth/health       - Health check
 * 
 * 🔐 PROTEGIDOS (requer autenticação):
 *   GET  /api/profile       - Ver perfil do usuário logado
 *   PUT  /api/profile       - Atualizar perfil
 *   GET  /api/orders        - Listar pedidos do usuário
 * 
 * 👑 ADMIN ONLY:
 *   GET  /api/admin/users   - Listar todos usuários
 *   DELETE /api/admin/users/{id} - Deletar usuário
 * 
 * 🔒 OWNER (apenas dono do recurso ou admin):
 *   GET  /api/users/{userId}/settings - Ver configurações do usuário
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
            
            ╔═══════════════════════════════════════════════════════════════╗
            ║          🔐 LazySpringSecurity Demo Application 🔐            ║
            ╠═══════════════════════════════════════════════════════════════╣
            ║                                                               ║
            ║  Endpoints disponíveis:                                       ║
            ║                                                               ║
            ║  📢 PÚBLICOS:                                                 ║
            ║     POST /auth/register  - Registrar usuário                  ║
            ║     POST /auth/login     - Login                              ║
            ║     GET  /auth/health    - Health check                       ║
            ║                                                               ║
            ║  🔐 AUTENTICADOS:                                             ║
            ║     GET  /api/profile    - Ver perfil                         ║
            ║     GET  /api/orders     - Listar pedidos                     ║
            ║                                                               ║
            ║  👑 ADMIN:                                                    ║
            ║     GET  /api/admin/users - Listar usuários                   ║
            ║                                                               ║
            ╚═══════════════════════════════════════════════════════════════╝
            """);
        
        SpringApplication.run(DemoApplication.class, args);
    }
}
