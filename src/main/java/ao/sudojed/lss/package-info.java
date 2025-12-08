/**
 * LazySpringSecurity (LSS) - A lightweight, annotation-driven security framework.
 * 
 * <h2>Quick Start</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(secret = "${app.jwt.secret}"),
 *     publicPaths = {"/api/public/**", "/health"}
 * )
 * @SpringBootApplication
 * public class MyApplication { }
 * }</pre>
 * 
 * <h2>Secure Endpoints</h2>
 * <pre>{@code
 * @LazySecured(roles = "ADMIN")
 * @GetMapping("/admin/dashboard")
 * public Dashboard getDashboard() { }
 * 
 * @Public
 * @PostMapping("/login")
 * public Token login() { }
 * }</pre>
 * 
 * @author Sudojed Team
 * @version 1.0.0
 */
package ao.sudojed.lss;
