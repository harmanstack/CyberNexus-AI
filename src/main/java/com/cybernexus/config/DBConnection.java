package com.cybernexus.config;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * DBConnection manages JDBC connections to the MySQL database.
 * Part of Harman's Backend Responsibilities.
 *
 * It securely loads database credentials from classpath resource 'database.properties'
 * and provides static factory methods to obtain and test connections.
 */
public final class DBConnection {

    private static final Properties PROPERTIES = new Properties();
    private static final String DRIVER_CLASS = "com.mysql.cj.jdbc.Driver";

    static {
        // Load database.properties from the application classpath (src/main/resources)
        try (InputStream input = DBConnection.class.getClassLoader()
                .getResourceAsStream("database.properties")) {
            if (input == null) {
                throw new IllegalStateException(
                        "Configuration file 'database.properties' was not found on the classpath!\n"
                                + "Please create 'src/main/resources/database.properties' with your MySQL credentials.");
            }
            PROPERTIES.load(input);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read 'database.properties'", e);
        }

        // Register the MySQL Type-4 JDBC Driver
        try {
            Class.forName(DRIVER_CLASS);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("MySQL JDBC Driver (" + DRIVER_CLASS + ") not found on classpath. "
                    + "Check your pom.xml for mysql-connector-j dependency.", e);
        }
    }

    // Private constructor prevents instantiation (Utility Class pattern)
    private DBConnection() {
    }

    /**
     * Establishes and returns an active Connection to the MySQL database.
     *
     * @return Connection object
     * @throws SQLException if a database access error occurs or credentials are wrong
     */
    public static Connection getConnection() throws SQLException {
        String url = PROPERTIES.getProperty("db.url");
        String user = PROPERTIES.getProperty("db.username");
        String password = PROPERTIES.getProperty("db.password");

        return DriverManager.getConnection(url, user, password);
    }

    /**
     * Tests the MySQL database connection and prints diagnostics.
     *
     * @return true if connection succeeds, false otherwise
     */
    public static boolean testConnection() {
        System.out.println("Attempting to connect to MySQL database at: " + PROPERTIES.getProperty("db.url"));
        try (Connection connection = getConnection()) {
            boolean isValid = connection != null && !connection.isClosed() && connection.isValid(2);
            if (isValid) {
                System.out.println("[SUCCESS] Successfully connected to MySQL database: "
                        + connection.getCatalog());
                return true;
            } else {
                System.err.println("[FAILURE] Connection was closed or invalid.");
                return false;
            }
        } catch (SQLException e) {
            System.err.println("[FAILURE] Database connection failed: " + e.getMessage());
            System.err.println("SQLState: " + e.getSQLState());
            System.err.println("ErrorCode: " + e.getErrorCode());
            return false;
        }
    }

    /**
     * Optional AI explanation endpoint; empty string means local heuristic fallback is used.
     */
    public static String getAiApiUrl() {
        String url = PROPERTIES.getProperty("ai.api.url");
        return url == null ? "" : url.trim();
    }

    /**
     * Standalone main method to test the database connection directly from IntelliJ IDEA.
     * Right-click inside this file and choose: Run 'DBConnection.main()'
     */
    public static void main(String[] args) {
        System.out.println("=== Testing MySQL Connection (CyberNexus AI - Harman) ===");
        boolean connected = testConnection();
        if (connected) {
            System.out.println(">>> Database is ready for UserDAO, ScanDAO, and AuthService! <<<");
        } else {
            System.out.println(">>> Please verify your MySQL server is running and check database.properties credentials. <<<");
        }
    }
}
