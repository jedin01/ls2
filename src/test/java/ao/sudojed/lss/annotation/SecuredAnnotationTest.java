package ao.sudojed.lss.annotation;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the @Secured annotation.
 *
 * This annotation unifies @LazySecured, @Authenticated, and @Admin
 * into a single, intuitive API.
 */
@DisplayName("@Secured Annotation Tests")
class SecuredAnnotationTest {

    // ==================== Basic Usage Tests ====================

    @Test
    @DisplayName("@Secured without parameters means 'authenticated only'")
    void securedWithoutParamsMeansAuthenticated() throws NoSuchMethodException {
        class TestController {

            @Secured
            public void protectedEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "protectedEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertEquals(0, secured.value().length, "value() should be empty");
        assertEquals(0, secured.roles().length, "roles() should be empty");
        assertEquals(
            0,
            secured.permissions().length,
            "permissions() should be empty"
        );
        assertFalse(secured.all(), "all() should default to false");
        assertEquals("Access denied", secured.message());
        assertEquals("", secured.condition());
    }

    @Test
    @DisplayName("@Secured(\"ADMIN\") requires ADMIN role")
    void securedWithSingleRole() throws NoSuchMethodException {
        class TestController {

            @Secured("ADMIN")
            public void adminEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod("adminEndpoint");
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(new String[] { "ADMIN" }, secured.value());
        assertEquals(0, secured.roles().length, "roles() should be empty");
        assertFalse(secured.all());
    }

    @Test
    @DisplayName("@Secured({\"ADMIN\", \"MANAGER\"}) requires any of the roles")
    void securedWithMultipleRoles() throws NoSuchMethodException {
        class TestController {

            @Secured({ "ADMIN", "MANAGER" })
            public void multiRoleEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "multiRoleEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(
            new String[] { "ADMIN", "MANAGER" },
            secured.value()
        );
        assertFalse(
            secured.all(),
            "all() should default to false (ANY logic)"
        );
    }

    @Test
    @DisplayName("@Secured with all=true requires ALL roles")
    void securedWithAllRolesRequired() throws NoSuchMethodException {
        class TestController {

            @Secured(value = { "VERIFIED", "PREMIUM" }, all = true)
            public void premiumEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "premiumEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(
            new String[] { "VERIFIED", "PREMIUM" },
            secured.value()
        );
        assertTrue(secured.all(), "all() should be true (AND logic)");
    }

    // ==================== Roles Attribute Tests ====================

    @Test
    @DisplayName("@Secured with roles attribute works as alias for value")
    void securedWithRolesAttribute() throws NoSuchMethodException {
        class TestController {

            @Secured(roles = { "USER", "EDITOR" })
            public void rolesEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod("rolesEndpoint");
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertEquals(0, secured.value().length, "value() should be empty");
        assertArrayEquals(
            new String[] { "USER", "EDITOR" },
            secured.roles()
        );
    }

    // ==================== Permissions Tests ====================

    @Test
    @DisplayName("@Secured with permissions requires specific permissions")
    void securedWithPermissions() throws NoSuchMethodException {
        class TestController {

            @Secured(permissions = { "users:read", "users:write" })
            public void permissionsEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "permissionsEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(
            new String[] { "users:read", "users:write" },
            secured.permissions()
        );
    }

    @Test
    @DisplayName("@Secured with roles and permissions")
    void securedWithRolesAndPermissions() throws NoSuchMethodException {
        class TestController {

            @Secured(roles = "USER", permissions = "posts:write")
            public void combinedEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "combinedEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(new String[] { "USER" }, secured.roles());
        assertArrayEquals(new String[] { "posts:write" }, secured.permissions());
    }

    // ==================== Condition Tests ====================

    @Test
    @DisplayName("@Secured with SpEL condition")
    void securedWithSpelCondition() throws NoSuchMethodException {
        class TestController {

            @Secured(condition = "#userId == principal.id")
            public void conditionalEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "conditionalEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertEquals("#userId == principal.id", secured.condition());
    }

    // ==================== Custom Message Tests ====================

    @Test
    @DisplayName("@Secured with custom error message")
    void securedWithCustomMessage() throws NoSuchMethodException {
        class TestController {

            @Secured(value = "ADMIN", message = "Only administrators can access this resource")
            public void customMessageEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "customMessageEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertEquals(
            "Only administrators can access this resource",
            secured.message()
        );
    }

    // ==================== Class-Level Annotation Tests ====================

    @Test
    @DisplayName("@Secured can be applied at class level")
    void securedAtClassLevel() {
        @Secured("ADMIN")
        class AdminController {

            public void adminMethod() {}
        }

        Secured secured = AdminController.class.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(new String[] { "ADMIN" }, secured.value());
    }

    // ==================== Migration Tests (comparing with deprecated annotations) ====================

    @Test
    @DisplayName("@Secured is equivalent to @Authenticated (deprecated)")
    void securedEquivalentToAuthenticated() throws NoSuchMethodException {
        // @Secured without params = @Authenticated = just needs to be logged in
        class TestController {

            @Secured
            public void authenticatedEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "authenticatedEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertEquals(
            0,
            secured.value().length,
            "No roles means 'any authenticated user'"
        );
        assertEquals(0, secured.roles().length);
        assertFalse(secured.all());
    }

    @Test
    @DisplayName("@Secured(\"ADMIN\") is equivalent to @Admin (deprecated)")
    void securedEquivalentToAdmin() throws NoSuchMethodException {
        // @Secured("ADMIN") = @Admin
        class TestController {

            @Secured("ADMIN")
            public void adminEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod("adminEndpoint");
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(new String[] { "ADMIN" }, secured.value());
    }

    @Test
    @DisplayName("@Secured with all=false is equivalent to @LazySecured with RoleLogic.ANY")
    void securedAnyEquivalentToLazySecuredAny() throws NoSuchMethodException {
        // @Secured({"A", "B"}) = @LazySecured(roles={"A","B"}, logic=RoleLogic.ANY)
        class TestController {

            @Secured({ "ADMIN", "MANAGER" })
            public void anyRoleEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "anyRoleEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(
            new String[] { "ADMIN", "MANAGER" },
            secured.value()
        );
        assertFalse(secured.all(), "all=false means ANY role is sufficient");
    }

    @Test
    @DisplayName("@Secured with all=true is equivalent to @LazySecured with RoleLogic.ALL")
    void securedAllEquivalentToLazySecuredAll() throws NoSuchMethodException {
        // @Secured(value={"A", "B"}, all=true) = @LazySecured(roles={"A","B"}, logic=RoleLogic.ALL)
        class TestController {

            @Secured(value = { "VERIFIED", "PREMIUM" }, all = true)
            public void allRolesEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "allRolesEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(
            new String[] { "VERIFIED", "PREMIUM" },
            secured.value()
        );
        assertTrue(secured.all(), "all=true means ALL roles are required");
    }

    // ==================== Full Configuration Test ====================

    @Test
    @DisplayName("@Secured with all attributes configured")
    void securedWithFullConfiguration() throws NoSuchMethodException {
        class TestController {

            @Secured(
                value = { "ADMIN", "SUPER_ADMIN" },
                permissions = { "system:manage", "users:delete" },
                all = true,
                message = "Super admin access required",
                condition = "#confirm == true"
            )
            public void fullConfigEndpoint() {}
        }

        Method method = TestController.class.getDeclaredMethod(
            "fullConfigEndpoint"
        );
        Secured secured = method.getAnnotation(Secured.class);

        assertNotNull(secured);
        assertArrayEquals(
            new String[] { "ADMIN", "SUPER_ADMIN" },
            secured.value()
        );
        assertArrayEquals(
            new String[] { "system:manage", "users:delete" },
            secured.permissions()
        );
        assertTrue(secured.all());
        assertEquals("Super admin access required", secured.message());
        assertEquals("#confirm == true", secured.condition());
    }
}
