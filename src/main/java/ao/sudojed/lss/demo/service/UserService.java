package ao.sudojed.lss.demo.service;

import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.util.PasswordUtils;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Serviço de usuários para demonstração.
 * Usa armazenamento em memória (em produção seria um repositório JPA).
 */
@Service
public class UserService {

    // Simula banco de dados em memória
    private final Map<String, User> usersById = new ConcurrentHashMap<>();
    private final Map<String, User> usersByUsername = new ConcurrentHashMap<>();

    public UserService() {
        // Cria usuários de demonstração
        initializeDemoUsers();
    }

    private void initializeDemoUsers() {
        // Admin padrão
        User admin = createUser("admin", "admin@example.com", "admin123");
        admin.addRole("ADMIN");
        admin.setDisplayName("Administrador");
        
        // Usuários de teste
        User john = createUser("john", "john@example.com", "123456");
        john.setDisplayName("John Doe");
        
        User jane = createUser("jane", "jane@example.com", "123456");
        jane.setDisplayName("Jane Smith");
        jane.addRole("MANAGER");
        
        System.out.println("""
            
            👥 Usuários de demonstração criados:
            ╔════════════════════════════════════════════════════╗
            ║  Username  │  Password  │  Roles                   ║
            ╠════════════════════════════════════════════════════╣
            ║  admin     │  admin123  │  USER, ADMIN             ║
            ║  john      │  123456    │  USER                    ║
            ║  jane      │  123456    │  USER, MANAGER           ║
            ╚════════════════════════════════════════════════════╝
            """);
    }

    /**
     * Cria um novo usuário.
     */
    public User createUser(String username, String email, String password) {
        String id = "user-" + UUID.randomUUID().toString().substring(0, 8);
        String passwordHash = PasswordUtils.hash(password);
        
        User user = new User(id, username, email, passwordHash);
        user.addRole("USER"); // Role padrão
        
        usersById.put(id, user);
        usersByUsername.put(username, user);
        
        return user;
    }

    /**
     * Busca usuário por ID.
     */
    public Optional<User> findById(String id) {
        return Optional.ofNullable(usersById.get(id));
    }

    /**
     * Busca usuário por username.
     */
    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(usersByUsername.get(username));
    }

    /**
     * Lista todos os usuários.
     */
    public List<User> findAll() {
        return new ArrayList<>(usersById.values());
    }

    /**
     * Salva/atualiza um usuário.
     */
    public User save(User user) {
        usersById.put(user.getId(), user);
        usersByUsername.put(user.getUsername(), user);
        return user;
    }

    /**
     * Deleta um usuário por ID.
     */
    public boolean deleteById(String id) {
        User user = usersById.remove(id);
        if (user != null) {
            usersByUsername.remove(user.getUsername());
            return true;
        }
        return false;
    }
}
