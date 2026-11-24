package com.cybernexus.dao;

import com.cybernexus.config.DBConnection;
import com.cybernexus.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * UserDAO (Data Access Object) handles all JDBC database operations for the 'users' table.
 * Part of Harman's Backend Responsibilities.
 *
 * Security & Design Principles:
 * 1. Strict use of PreparedStatement to completely prevent SQL Injection.
 * 2. Try-with-resources blocks to guarantee Connection, PreparedStatement, and ResultSet are closed.
 * 3. Encapsulates all SQL syntax so higher layers (AuthService, ConsoleUI) remain database-agnostic.
 */
public class UserDAO {

    /**
     * Checks whether an email already exists in the users table.
     *
     * @param email user's email to verify
     * @return true if email already exists, false otherwise
     * @throws SQLException if a database access error occurs
     */
    public boolean emailExists(String email) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, email.trim());
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    /**
     * Checks whether a username already exists in the users table.
     *
     * @param username user's username/name to verify
     * @return true if username exists, false otherwise
     * @throws SQLException if a database access error occurs
     */
    public boolean usernameExists(String username) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE LOWER(name) = LOWER(?) LIMIT 1";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username.trim());
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    /**
     * Inserts a new user record into the users table.
     *
     * @param user User object containing name, email, passwordHash, and role
     * @return true if insertion succeeded (1 row affected), false otherwise
     * @throws SQLException if a database access error occurs
     */
    public boolean createUser(User user) throws SQLException {
        String sql = "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, user.getName().trim());
            statement.setString(2, user.getEmail().trim().toLowerCase());
            statement.setString(3, user.getPasswordHash());
            statement.setString(4, user.getRole() == null ? "user" : user.getRole().trim());

            int rowsAffected = statement.executeUpdate();
            return rowsAffected == 1;
        }
    }

    /**
     * Finds a user by their email address.
     *
     * @param email the email to search for
     * @return User object if found, or null if no user matches
     * @throws SQLException if a database access error occurs
     */
    public User findByEmail(String email) throws SQLException {
        String sql = "SELECT user_id, name, email, password_hash, role, created_at "
                + "FROM users WHERE LOWER(email) = LOWER(?)";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, email.trim());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return mapUser(result);
            }
        }
    }

    /**
     * Finds a user by their username/name.
     *
     * @param username the username to search for
     * @return User object if found, or null if no user matches
     * @throws SQLException if a database access error occurs
     */
    public User findByUsername(String username) throws SQLException {
        String sql = "SELECT user_id, name, email, password_hash, role, created_at "
                + "FROM users WHERE LOWER(name) = LOWER(?)";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username.trim());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return mapUser(result);
            }
        }
    }

    /**
     * Finds a user by either their email or username.
     *
     * @param identifier candidate email or username
     * @return User object if found, or null otherwise
     * @throws SQLException if a database access error occurs
     */
    public User findByEmailOrUsername(String identifier) throws SQLException {
        User user = findByEmail(identifier);
        if (user != null) {
            return user;
        }
        return findByUsername(identifier);
    }

    /**
     * Finds a user by their primary key user_id.
     *
     * @param userId the user's ID
     * @return User object if found, or null otherwise
     * @throws SQLException if a database access error occurs
     */
    public User findById(int userId) throws SQLException {
        String sql = "SELECT user_id, name, email, password_hash, role, created_at "
                + "FROM users WHERE user_id = ?";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return mapUser(result);
            }
        }
    }

    /**
     * Retrieves the total count of registered users in the database.
     *
     * @return total user count
     * @throws SQLException if a database access error occurs
     */
    public int countUsers() throws SQLException {
        String sql = "SELECT COUNT(*) FROM users";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {
            result.next();
            return result.getInt(1);
        }
    }

    /**
     * Retrieves all registered users ordered by creation date (newest first).
     *
     * @return List of User objects
     * @throws SQLException if a database access error occurs
     */
    public List<User> findAll() throws SQLException {
        String sql = "SELECT user_id, name, email, password_hash, role, created_at "
                + "FROM users ORDER BY created_at DESC";
        List<User> users = new ArrayList<>();
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                users.add(mapUser(result));
            }
        }
        return users;
    }

    /**
     * Maps the current row of a JDBC ResultSet to a User domain model.
     *
     * @param result active ResultSet cursor positioned at a valid row
     * @return User model instance
     * @throws SQLException if column reading fails
     */
    private User mapUser(ResultSet result) throws SQLException {
        Timestamp created = result.getTimestamp("created_at");
        return new User(
                result.getInt("user_id"),
                result.getString("name"),
                result.getString("email"),
                result.getString("password_hash"),
                result.getString("role"),
                created == null ? null : created.toLocalDateTime());
    }

    /**
     * Standalone main method to test UserDAO queries.
     * Note: Requires running MySQL server with schema.sql applied.
     */
    public static void main(String[] args) {
        System.out.println("=== Testing UserDAO (Harman) ===");
        UserDAO dao = new UserDAO();
        try {
            int count = dao.countUsers();
            System.out.println("[SUCCESS] Database connected! Current total users in MySQL: " + count);
        } catch (SQLException e) {
            System.err.println("[INFO] Could not query database (MySQL may be offline): " + e.getMessage());
        }
    }
}
