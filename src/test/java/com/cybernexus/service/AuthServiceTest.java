package com.cybernexus.service;

import com.cybernexus.dao.UserDAO;
import com.cybernexus.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AuthService validation and authentication logic.
 * Uses a stubbed UserDAO to test business rules deterministically.
 */
class AuthServiceTest {

    private AuthService authService;
    private StubUserDAO stubUserDAO;

    @BeforeEach
    void setUp() {
        stubUserDAO = new StubUserDAO();
        authService = new AuthService(stubUserDAO);
    }

    @Test
    @DisplayName("Should reject registration with name shorter than 3 characters")
    void testRegisterShortName() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                authService.register("Al", "al@example.com", "Password123"));
        assertTrue(ex.getMessage().contains("at least 3 characters"));
    }

    @Test
    @DisplayName("Should reject registration with invalid email format")
    void testRegisterInvalidEmail() {
        assertThrows(IllegalArgumentException.class, () ->
                authService.register("Harman", "invalid-email-address", "Password123"));
    }

    @Test
    @DisplayName("Should reject registration with password shorter than 8 characters")
    void testRegisterShortPassword() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                authService.register("Harman", "harman@example.com", "1234567"));
        assertTrue(ex.getMessage().contains("at least 8 characters"));
    }

    @Test
    @DisplayName("Should reject registration with spaces in password")
    void testRegisterPasswordWithSpaces() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                authService.register("Harman", "harman@example.com", "Pass word 123"));
        assertTrue(ex.getMessage().contains("cannot contain spaces"));
    }

    @Test
    @DisplayName("Should reject registration if email is already taken")
    void testRegisterDuplicateEmail() throws SQLException {
        authService.register("UserOne", "duplicate@example.com", "Password123");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                authService.register("UserTwo", "duplicate@example.com", "Password123"));
        assertTrue(ex.getMessage().contains("already exists"));
    }

    @Test
    @DisplayName("Should successfully authenticate valid user and reject invalid password")
    void testLoginFlow() throws SQLException {
        authService.register("Harman", "harman@cybernexus.com", "SecurePassword123");

        // Valid login by email
        User loggedInUser = authService.login("harman@cybernexus.com", "SecurePassword123");
        assertNotNull(loggedInUser);
        assertEquals("Harman", loggedInUser.getName());

        // Valid login by username
        User loggedInByUsername = authService.login("Harman", "SecurePassword123");
        assertNotNull(loggedInByUsername);

        // Invalid password
        User wrongPassword = authService.login("harman@cybernexus.com", "WrongPassword999");
        assertNull(wrongPassword, "Login with wrong password must return null");

        // Non-existent user
        User nonExistent = authService.login("ghost@cybernexus.com", "SecurePassword123");
        assertNull(nonExistent, "Login with non-existent user must return null");
    }

    /**
     * In-memory stub of UserDAO for unit testing without live MySQL database.
     */
    private static class StubUserDAO extends UserDAO {
        private final Map<String, User> emailDb = new HashMap<>();
        private final Map<String, User> usernameDb = new HashMap<>();
        private int idCounter = 1;

        @Override
        public boolean emailExists(String email) {
            return emailDb.containsKey(email.trim().toLowerCase());
        }

        @Override
        public boolean usernameExists(String username) {
            return usernameDb.containsKey(username.trim().toLowerCase());
        }

        @Override
        public boolean createUser(User user) {
            user.setId(idCounter++);
            emailDb.put(user.getEmail().toLowerCase(), user);
            usernameDb.put(user.getName().toLowerCase(), user);
            return true;
        }

        @Override
        public User findByEmail(String email) {
            return emailDb.get(email.trim().toLowerCase());
        }

        @Override
        public User findByUsername(String username) {
            return usernameDb.get(username.trim().toLowerCase());
        }
    }
}
