package ao.sudojed.lss.integration;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import ao.sudojed.lss.annotation.*;
import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.jwt.TokenPair;
import ao.sudojed.lss.util.LazyAuth;
import ao.sudojed.lss.util.PasswordUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.*;

/**
 * Complete integration test for LazySpringSecurity.
 * Simulates a real application with JWT authentication and access control.
 */
@SpringBootTest(
    classes = LssIntegrationTest.TestApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LssIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    private static String userToken;
    private static String adminToken;

    @BeforeAll
    static void setupTokens(@Autowired JwtService jwtService) {
        // Create regular user token
        LazyUser user = LazyUser.builder()
            .id("user-123")
            .username("john.doe")
            .roles("USER")
            .permissions("posts:read")
            .claim("email", "john@example.com")
            .build();
        userToken = jwtService.createTokens(user).accessToken();

        // Create admin token
        LazyUser admin = LazyUser.builder()
            .id("admin-456")
            .username("admin")
            .roles("ADMIN", "USER")
            .permissions("posts:read", "posts:write", "users:manage")
            .build();
        adminToken = jwtService.createTokens(admin).accessToken();
    }

    // ==================== Public Endpoint Tests ====================

    @Test
    @Order(1)
    @DisplayName("@Public endpoint should be accessible without token")
    void publicEndpointShouldBeAccessibleWithoutToken() throws Exception {
        mockMvc
            .perform(get("/api/public/health"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    @Order(2)
    @DisplayName("Login should return JWT tokens")
    void loginShouldReturnTokens() throws Exception {
        String loginRequest = """
            {
                "username": "john.doe",
                "password": "secret123"
            }
            """;

        MvcResult result = mockMvc
            .perform(
                post("/api/public/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(loginRequest)
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.refresh_token").exists())
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andReturn();

        System.out.println(
            "Login Response: " + result.getResponse().getContentAsString()
        );
    }

    // ==================== Authentication Tests ====================

    @Test
    @Order(3)
    @DisplayName("Protected endpoint should return 401 without token")
    void protectedEndpointShouldReturn401WithoutToken() throws Exception {
        mockMvc
            .perform(get("/api/profile"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    @Order(4)
    @DisplayName("Protected endpoint should return 401 with invalid token")
    void protectedEndpointShouldReturn401WithInvalidToken() throws Exception {
        mockMvc
            .perform(
                get("/api/profile").header(
                    "Authorization",
                    "Bearer invalid.token.here"
                )
            )
            .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    @DisplayName("@Secured endpoint should accept valid token")
    void protectedEndpointShouldAcceptValidToken() throws Exception {
        mockMvc
            .perform(
                get("/api/profile").header(
                    "Authorization",
                    "Bearer " + userToken
                )
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value("user-123"))
            .andExpect(jsonPath("$.username").value("john.doe"));
    }

    // ==================== Role-Based Authorization Tests ====================

    @Test
    @Order(6)
    @DisplayName("Regular user CANNOT access @Secured(\"ADMIN\") endpoint")
    void regularUserCannotAccessAdminEndpoint() throws Exception {
        mockMvc
            .perform(
                get("/api/admin/users").header(
                    "Authorization",
                    "Bearer " + userToken
                )
            )
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    @Order(7)
    @DisplayName("Admin CAN access @Secured(\"ADMIN\") endpoint")
    void adminCanAccessAdminEndpoint() throws Exception {
        mockMvc
            .perform(
                get("/api/admin/users").header(
                    "Authorization",
                    "Bearer " + adminToken
                )
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
    }

    @Test
    @Order(8)
    @DisplayName("Endpoint with multiple roles accepts any of them")
    void multipleRolesAcceptsAny() throws Exception {
        // User tem role USER
        mockMvc
            .perform(
                get("/api/dashboard").header(
                    "Authorization",
                    "Bearer " + userToken
                )
            )
            .andExpect(status().isOk());

        // Admin também pode
        mockMvc
            .perform(
                get("/api/dashboard").header(
                    "Authorization",
                    "Bearer " + adminToken
                )
            )
            .andExpect(status().isOk());
    }

    // ==================== @Owner Tests ====================

    @Test
    @Order(9)
    @DisplayName("User can access their own data with @Owner")
    void userCanAccessOwnData() throws Exception {
        mockMvc
            .perform(
                get("/api/users/user-123/orders").header(
                    "Authorization",
                    "Bearer " + userToken
                )
            )
            .andExpect(status().isOk());
    }

    @Test
    @Order(10)
    @DisplayName("User CANNOT access another user's data with @Owner")
    void userCannotAccessOthersData() throws Exception {
        mockMvc
            .perform(
                get("/api/users/other-user-999/orders").header(
                    "Authorization",
                    "Bearer " + userToken
                )
            )
            .andExpect(status().isForbidden());
    }

    @Test
    @Order(11)
    @DisplayName("Admin can bypass @Owner")
    void adminCanBypassOwner() throws Exception {
        mockMvc
            .perform(
                get("/api/users/other-user-999/orders").header(
                    "Authorization",
                    "Bearer " + adminToken
                )
            )
            .andExpect(status().isOk());
    }

    // ==================== LazyUser Injection Tests ====================

    @Test
    @Order(12)
    @DisplayName("LazyUser is automatically injected into controller")
    void lazyUserIsInjectedAutomatically() throws Exception {
        mockMvc
            .perform(
                get("/api/me").header("Authorization", "Bearer " + userToken)
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userId").value("user-123"))
            .andExpect(jsonPath("$.username").value("john.doe"))
            .andExpect(jsonPath("$.isAdmin").value(false));
    }

    // ==================== PasswordUtils Test ====================

    @Test
    @Order(13)
    @DisplayName("PasswordUtils should hash and validate passwords")
    void passwordUtilsShouldHashAndValidate() {
        String rawPassword = "mySecretPassword123";

        // Hash
        String hash = PasswordUtils.hash(rawPassword);
        assertNotNull(hash);
        assertNotEquals(rawPassword, hash);
        assertTrue(hash.startsWith("$2a$")); // BCrypt prefix

        // Validação
        assertTrue(PasswordUtils.matches(rawPassword, hash));
        assertFalse(PasswordUtils.matches("wrongPassword", hash));

        System.out.println("Password Hash: " + hash);
    }

    // ==================== Test Application ====================

    @EnableLazySecurity(
        jwt = @JwtConfig(
            secret = "my-super-secret-key-for-testing-that-is-at-least-32-chars"
        ),
        publicPaths = { "/api/public/**" },
        debug = true
    )
    @SpringBootApplication(scanBasePackages = "ao.sudojed.lss.integration")
    static class TestApplication {}
}
