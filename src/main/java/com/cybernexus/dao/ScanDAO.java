package com.cybernexus.dao;

import com.cybernexus.config.DBConnection;
import com.cybernexus.model.Scan;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ScanDAO (Data Access Object) handles all JDBC persistence for threat scans.
 * Part of Harman's Backend Responsibilities.
 *
 * Coordinates data persistence with Tanisha's detection results and Aarchi's UI history views:
 * - Stores scan records with auto-generated primary keys.
 * - Retrieves chronological scan history for individual authenticated users.
 * - Supports aggregate JOIN queries for administrative statistics.
 */
public class ScanDAO {

    /**
     * Persists a completed scan into MySQL and assigns the generated scan_id to the Scan object.
     *
     * @param scan the Scan entity containing userId, scanType, inputData, riskScore, riskLevel, and detectionReason
     * @return the auto-generated scan_id (primary key), or -1 if insertion failed
     * @throws IllegalArgumentException if riskScore is out of the 0-100 range or scan is null
     * @throws SQLException             if a database access error occurs (e.g. foreign key user_id does not exist)
     */
    public int saveScan(Scan scan) throws SQLException {
        if (scan == null) {
            throw new IllegalArgumentException("Scan entity cannot be null");
        }
        if (scan.getRiskScore() < 0 || scan.getRiskScore() > 100) {
            throw new IllegalArgumentException("Risk score must be between 0 and 100 (provided: " + scan.getRiskScore() + ")");
        }

        String sql = "INSERT INTO scans "
                + "(user_id, scan_type, input_data, risk_score, risk_level, detection_reason) "
                + "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            statement.setInt(1, scan.getUserId());
            statement.setString(2, scan.getScanType());
            statement.setString(3, scan.getInputData());
            statement.setInt(4, scan.getRiskScore());
            statement.setString(5, scan.getRiskLevel());
            statement.setString(6, scan.getDetectionReason());

            int rowsAffected = statement.executeUpdate();
            if (rowsAffected != 1) {
                return -1;
            }

            // Retrieve the auto-generated scan_id primary key from MySQL
            try (ResultSet generatedKeys = statement.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    int generatedId = generatedKeys.getInt(1);
                    scan.setId(generatedId);
                    return generatedId;
                }
            }
            return -1;
        }
    }

    /**
     * Retrieves all scan history records for a specific user, sorted from newest to oldest.
     *
     * @param userId the ID of the authenticated user
     * @return List of Scan objects for this user
     * @throws SQLException if a database error occurs
     */
    public List<Scan> findByUserId(int userId) throws SQLException {
        String sql = "SELECT scan_id, user_id, scan_type, input_data, risk_score, "
                + "risk_level, detection_reason, created_at "
                + "FROM scans WHERE user_id = ? ORDER BY created_at DESC";

        List<Scan> scans = new ArrayList<>();
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    scans.add(mapScan(result));
                }
            }
        }
        return scans;
    }

    /**
     * Retrieves all scan records across all users in the system (for admin review).
     *
     * @return List of all Scan objects
     * @throws SQLException if a database error occurs
     */
    public List<Scan> findAll() throws SQLException {
        String sql = "SELECT scan_id, user_id, scan_type, input_data, risk_score, "
                + "risk_level, detection_reason, created_at "
                + "FROM scans ORDER BY created_at DESC";

        List<Scan> scans = new ArrayList<>();
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            while (result.next()) {
                scans.add(mapScan(result));
            }
        }
        return scans;
    }

    /**
     * Computes per-user scan statistics using a SQL LEFT JOIN.
     * Users who haven't performed any scans will still appear with scan_count = 0.
     *
     * @return List of statistical summary rows
     * @throws SQLException if a database error occurs
     */
    public List<Map<String, Object>> userScanStatistics() throws SQLException {
        String sql = "SELECT u.user_id, u.name, u.email, u.role, "
                + "COUNT(s.scan_id) AS scan_count, "
                + "COALESCE(AVG(s.risk_score), 0) AS avg_score, "
                + "SUM(CASE WHEN s.risk_level = 'HIGH' THEN 1 ELSE 0 END) AS high_count "
                + "FROM users u LEFT JOIN scans s ON u.user_id = s.user_id "
                + "GROUP BY u.user_id, u.name, u.email, u.role "
                + "ORDER BY scan_count DESC";

        List<Map<String, Object>> rows = new ArrayList<>();
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            while (result.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("userId", result.getInt("user_id"));
                row.put("name", result.getString("name"));
                row.put("email", result.getString("email"));
                row.put("role", result.getString("role"));
                row.put("scanCount", result.getInt("scan_count"));
                row.put("averageScore", result.getDouble("avg_score"));
                row.put("highCount", result.getInt("high_count"));
                rows.add(row);
            }
        }
        return rows;
    }

    /**
     * Retrieves the grand total number of scans stored in MySQL.
     *
     * @return total scan count
     * @throws SQLException if a database error occurs
     */
    public int countScans() throws SQLException {
        String sql = "SELECT COUNT(*) FROM scans";
        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            result.next();
            return result.getInt(1);
        }
    }

    /**
     * Helper method to map an active ResultSet row to a Scan entity.
     */
    private Scan mapScan(ResultSet result) throws SQLException {
        Timestamp created = result.getTimestamp("created_at");
        return new Scan(
                result.getInt("scan_id"),
                result.getInt("user_id"),
                result.getString("scan_type"),
                result.getString("input_data"),
                result.getInt("risk_score"),
                result.getString("risk_level"),
                result.getString("detection_reason"),
                created == null ? null : created.toLocalDateTime());
    }

    /**
     * Standalone main method to test ScanDAO.
     */
    public static void main(String[] args) {
        System.out.println("=== Testing ScanDAO (Harman) ===");
        ScanDAO dao = new ScanDAO();
        try {
            int count = dao.countScans();
            System.out.println("[SUCCESS] Database connected! Total scans recorded in MySQL: " + count);
        } catch (SQLException e) {
            System.err.println("[INFO] Could not query database (MySQL may be offline): " + e.getMessage());
        }
    }
}
