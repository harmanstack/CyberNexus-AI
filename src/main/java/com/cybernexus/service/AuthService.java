package com.cybernexus.service;

import com.cybernexus.dao.UserDAO;
import com.cybernexus.model.User;
import com.cybernexus.util.InputValidator;
import com.cybernexus.util.PasswordUtil;

import java.sql.SQLException;

/**
 * AuthService implements the core business and authentication logic.
 * Part of Harman's Backend Responsibilities.
 *
 * Responsibilities:
 * 1. User registration with comprehensive input validation.
 * 2. Duplicate account prevention (both email and username).
 * 3. Secure password hashing before database storage.
 * 4. User login authentication and password verification.
 */
public class AuthService {

    private final UserDAO userDAO;

    /**
     * Default constructor creates a standard UserDAO.
     */
    public AuthService() {
        this(new UserDAO());
    }

    /**
     * Parameterized constructor supports Dependency Injection (useful for unit testing).
     *
     * @param userDAO the DAO to interact with the database
     */
    public AuthService(UserDAO userDAO) {
        if (userDAO == null) {
            throw new IllegalArgumentException("UserDAO cannot be null");
        }
        this.userDAO = userDAO;
    }

    /**
     * Registers a new user account.
     *
     * @param name     user's full name or username
     * @param email    user's email address
     * @param password raw plain-text password (must be >= 8 chars)
     * @return the newly created User object retrieved from MySQL
     * @throws IllegalArgumentException if validation fails or duplicate account exists
     * @throws SQLException             if a database error occurs
     */
    public User register(String name, String email, String password) throws SQLException {
        // 1. Validate name / username
        String trimmedName = InputValidator.requireText(name, "Username / Name");
        if (trimmedName.length() < 3) {
            throw new IllegalArgumentException("Name / Username must be at least 3 characters long");
        }

        // 2. Validate email format
        String normalizedEmail = InputValidator.requireEmail(email);

        // 3. Validate password strength
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        if (password.contains(" ")) {
            throw new IllegalArgumentException("Password cannot contain spaces");
        }

        // 4. Duplicate Checks (Email and Username)
        if (userDAO.emailExists(normalizedEmail)) {
            throw new IllegalArgumentException("An account with email '" + normalizedEmail + "' already exists");
        }
        if (userDAO.usernameExists(trimmedName)) {
            throw new IllegalArgumentException("Username '" + trimmedName + "' is already taken");
        }

        // 5. Hash password with BCrypt
        String hashedPassword = PasswordUtil.hash(password);

        // 6. Build User entity
        User newUser = new User(trimmedName, normalizedEmail, hashedPassword, "user");

        // 7. Persist to MySQL via UserDAO
        boolean created = userDAO.createUser(newUser);
        if (!created) {
            throw new SQLException("Failed to create user record in database");
        }

        // 8. Fetch and return persisted user (including auto-generated user_id and created_at)
        return userDAO.findByEmail(normalizedEmail);
    }

    /**
     * Authenticates a user by email or username and password.
     * Compatible with Aarchi's ConsoleUI.
     *
     * @param identifier user's email address or username
     * @param password   user's plain-text password
     * @return authenticated User object if credentials are valid, or null otherwise
     * @throws SQLException if a database error occurs
     */
    public User login(String identifier, String password) throws SQLException {
        if (identifier == null || identifier.isBlank() || password == null || password.isBlank()) {
            return null;
        }

        String trimmedId = identifier.trim();

        // 1. Fetch user by email or username
        User user;
        if (InputValidator.isValidEmail(trimmedId)) {
            user = userDAO.findByEmail(trimmedId.toLowerCase());
        } else {
            user = userDAO.findByUsername(trimmedId);
        }

        // If no user found with this email/username
        if (user == null) {
            return null;
        }

        // 2. Verify password against stored BCrypt hash
        if (!PasswordUtil.matches(password, user.getPasswordHash())) {
            return null;
        }

        // Authentication successful
        return user;
    }

    /**
     * Standalone main method to test AuthService logic.
     */
    public static void main(String[] args) {
        System.out.println("=== Testing AuthService (Harman) ===");
        AuthService authService = new AuthService();
        try {
            System.out.println("Testing input validation: attempting to register with empty password...");
            authService.register("TestUser", "test@example.com", "123");
            System.err.println("[FAILURE] Validation did not catch short password!");
        } catch (IllegalArgumentException e) {
            System.out.println("[SUCCESS] Validation correctly caught invalid input: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("[INFO] Database access: " + e.getMessage());
        }
    }
}
