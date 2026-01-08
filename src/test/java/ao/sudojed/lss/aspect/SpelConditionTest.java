package ao.sudojed.lss.aspect;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import ao.sudojed.lss.annotation.EnableLazySecurity;
import ao.sudojed.lss.annotation.JwtConfig;
import ao.sudojed.lss.annotation.Secured;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.jwt.JwtService;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;

/**
 * Tests for SpEL condition evaluation in @Secured annotation.
 */
@SpringBootTest(
    classes = SpelConditionTest.TestApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@AutoConfigureMockMvc
@DisplayName("SpEL Condition Evaluation Tests")
@Disabled(
    "Temporarily disabled due to Spring Security configuration conflicts - will be fixed in future version"
)
class SpelConditionTest {

    @Autowired
    private MockMvc mockMvc;

    private static String user123Token;
    private static String user456Token;
    private static String adminToken;

    @BeforeAll
    static void setupTokens(@Autowired JwtService jwtService) {
        // User with ID "123"
        LazyUser user123 = LazyUser.builder()
            .id("123")
            .username("john")
            .roles("USER")
            .claim("department", "engineering")
            .claim("level", 5)
            .build();
        user123Token = jwtService.createTokens(user123).accessToken();

        // User with ID "456"
        LazyUser user456 = LazyUser.builder()
            .id("456")
            .username("jane")
            .roles("USER")
            .claim("department", "sales")
            .claim("level", 3)
            .build();
        user456Token = jwtService.createTokens(user456).accessToken();

        // Admin user
        LazyUser admin = LazyUser.builder()
            .id("admin-1")
            .username("admin")
            .roles("ADMIN", "USER")
            .claim("level", 10)
            .build();
        adminToken = jwtService.createTokens(admin).accessToken();
    }

    // ==================== Basic SpEL Condition Tests ====================

    @Test
    @DisplayName(
        "User can access their own resource with #userId == principal.id"
    )
    void userCanAccessOwnResource() throws Exception {
        mockMvc
            .perform(
                get("/api/spel/users/123/data").header(
                    "Authorization",
                    "Bearer " + user123Token
                )
            )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userId").value("123"));
    }

    @Test
    @DisplayName(
        "User CANNOT access another user's resource with #userId == principal.id"
    )
    void userCannotAccessOthersResource() throws Exception {
        mockMvc
            .perform(
                get("/api/spel/users/456/data").header(
                    "Authorization",
                    "Bearer " + user123Token
                )
            )
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Admin can access any resource with admin bypass in SpEL")
    void adminCanAccessAnyResource() throws Exception {
        mockMvc
            .perform(
                get("/api/spel/users/123/admin-or-owner").header(
                    "Authorization",
                    "Bearer " + adminToken
                )
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Owner can access with admin bypass in SpEL")
    void ownerCanAccessWithAdminBypass() throws Exception {
        mockMvc
            .perform(
                get("/api/spel/users/123/admin-or-owner").header(
                    "Authorization",
                    "Bearer " + user123Token
                )
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Non-owner non-admin CANNOT access with admin bypass in SpEL")
    void nonOwnerNonAdminCannotAccess() throws Exception {
        mockMvc
            .perform(
                get("/api/spel/users/123/admin-or-owner").header(
                    "Authorization",
                    "Bearer " + user456Token
                )
            )
            .andExpect(status().isForbidden());
    }

    // ==================== Claim-based SpEL Tests ====================

    @Test
    @DisplayName(
        "User with sufficient level can access level-restricted resource"
    )
    void userWithSufficientLevelCanAccess() throws Exception {
        // user123 has level 5, minimum is 4
        mockMvc
            .perform(
                get("/api/spel/level-restricted").header(
                    "Authorization",
                    "Bearer " + user123Token
                )
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName(
        "User with insufficient level CANNOT access level-restricted resource"
    )
    void userWithInsufficientLevelCannotAccess() throws Exception {
        // user456 has level 3, minimum is 4
        mockMvc
            .perform(
                get("/api/spel/level-restricted").header(
                    "Authorization",
                    "Bearer " + user456Token
                )
            )
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("User from specific department can access department resource")
    void userFromDepartmentCanAccess() throws Exception {
        // user123 is from "engineering"
        mockMvc
            .perform(
                get("/api/spel/engineering-only").header(
                    "Authorization",
                    "Bearer " + user123Token
                )
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName(
        "User from different department CANNOT access department resource"
    )
    void userFromDifferentDepartmentCannotAccess() throws Exception {
        // user456 is from "sales", not "engineering"
        mockMvc
            .perform(
                get("/api/spel/engineering-only").header(
                    "Authorization",
                    "Bearer " + user456Token
                )
            )
            .andExpect(status().isForbidden());
    }

    // ==================== Complex SpEL Expressions ====================

    @Test
    @DisplayName("Complex SpEL with multiple conditions")
    void complexSpelWithMultipleConditions() throws Exception {
        // user123: level 5, department engineering - should pass
        mockMvc
            .perform(
                get("/api/spel/complex").header(
                    "Authorization",
                    "Bearer " + user123Token
                )
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SpEL with method parameter comparison")
    void spelWithMethodParameterComparison() throws Exception {
        // user123 requesting amount 500 (< 1000), should pass
        mockMvc
            .perform(
                get("/api/spel/amount-check")
                    .param("amount", "500")
                    .header("Authorization", "Bearer " + user123Token)
            )
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SpEL with method parameter comparison - exceeds limit")
    void spelWithMethodParameterComparisonExceedsLimit() throws Exception {
        // user123 requesting amount 1500 (> 1000), should fail
        mockMvc
            .perform(
                get("/api/spel/amount-check")
                    .param("amount", "1500")
                    .header("Authorization", "Bearer " + user123Token)
            )
            .andExpect(status().isForbidden());
    }

    // ==================== Test Controller ====================

    @RestController
    @RequestMapping("/api/spel")
    static class SpelTestController {

        @Secured(condition = "#userId == #principal.id")
        @GetMapping("/users/{userId}/data")
        public Map<String, Object> getUserData(@PathVariable String userId) {
            return Map.of("userId", userId, "message", "Access granted");
        }

        @Secured(condition = "#principal.isAdmin() or #userId == #principal.id")
        @GetMapping("/users/{userId}/admin-or-owner")
        public Map<String, Object> getAdminOrOwnerData(
            @PathVariable String userId
        ) {
            return Map.of(
                "userId",
                userId,
                "message",
                "Access granted (admin or owner)"
            );
        }

        @Secured(condition = "#principal.getClaim('level', 0) >= 4")
        @GetMapping("/level-restricted")
        public Map<String, Object> getLevelRestricted() {
            return Map.of("message", "Access granted - level 4+");
        }

        @Secured(
            condition = "#principal.getClaim('department', '') == 'engineering'"
        )
        @GetMapping("/engineering-only")
        public Map<String, Object> getEngineeringOnly() {
            return Map.of("message", "Access granted - engineering dept");
        }

        @Secured(
            condition = "#principal.getClaim('level', 0) >= 4 and #principal.getClaim('department', '') == 'engineering'"
        )
        @GetMapping("/complex")
        public Map<String, Object> getComplexRestricted() {
            return Map.of(
                "message",
                "Access granted - level 4+ AND engineering"
            );
        }

        @Secured(condition = "#amount < 1000")
        @GetMapping("/amount-check")
        public Map<String, Object> getAmountCheck(
            @RequestParam Integer amount
        ) {
            return Map.of("amount", amount, "message", "Amount check passed");
        }
    }

    // ==================== Test Application ====================

    @EnableLazySecurity(
        jwt = @JwtConfig(
            secret = "spel-test-secret-key-that-is-at-least-32-characters-long"
        ),
        publicPaths = { "/error" },
        debug = true
    )
    @SpringBootApplication(scanBasePackages = "ao.sudojed.lss")
    static class TestApplication {}
}
