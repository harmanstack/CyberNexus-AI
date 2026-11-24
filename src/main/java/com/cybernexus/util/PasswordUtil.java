package com.cybernexus.util;

import org.mindrot.jbcrypt.BCrypt;

/**
 * PasswordUtil provides secure password hashing and verification using the BCrypt algorithm.
 * Part of Harman's Backend Responsibilities.
 *
 * Security Guarantees:
 * 1. Passwords are never stored in plain text.
 * 2. Automatic unique salt generation per password to defeat rainbow table attacks.
 * 3. Resistant to brute-force attacks via configurable key derivation work factor.
 */
public final class PasswordUtil {

    // Default BCrypt work factor (log2 rounds: 2^10 = 1024 iterations)
    private static final int BCRYPT_LOG_ROUNDS = 10;

    // Utility class: private constructor prevents instantiation
    private PasswordUtil() {
    }

    /**
     * Hashes a plain-text password using the BCrypt algorithm with a random salt.
     *
     * @param plainPassword the user's raw password
     * @return a 60-character BCrypt hash string
     * @throws IllegalArgumentException if plainPassword is null or empty
     */
    public static String hash(String plainPassword) {
        if (plainPassword == null || plainPassword.isBlank()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        // BCrypt.gensalt(BCRYPT_LOG_ROUNDS) generates a cryptographically secure random salt
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(BCRYPT_LOG_ROUNDS));
    }

    /**
     * Verifies whether a candidate plain-text password matches a stored BCrypt hash.
     *
     * @param plainPassword the plain-text password attempted during login
     * @param storedHash    the 60-character hash stored in the MySQL database
     * @return true if password matches, false if it does not match or if inputs are invalid
     */
    public static boolean matches(String plainPassword, String storedHash) {
        if (plainPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return BCrypt.checkpw(plainPassword, storedHash);
        } catch (IllegalArgumentException e) {
            // Catches malformed or invalid hash formats safely
            return false;
        }
    }

    /**
     * Standalone main method to test password hashing and verification.
     * Right-click inside this file and select: Run 'PasswordUtil.main()'
     */
    public static void main(String[] args) {
        System.out.println("=== Testing PasswordUtil (BCrypt Security - Harman) ===");

        String originalPassword = "SecretPassword@2026";
        System.out.println("1. Plain Password: " + originalPassword);

        // Generate Hash
        String hash1 = hash(originalPassword);
        System.out.println("2. Generated BCrypt Hash 1: " + hash1);
        System.out.println("   Hash Length: " + hash1.length() + " characters (strictly 60 chars)");

        // Demonstrate Salting: Even the same password produces a completely different hash!
        String hash2 = hash(originalPassword);
        System.out.println("3. Generated BCrypt Hash 2 (same password): " + hash2);
        System.out.println("   Are hashes identical? " + hash1.equals(hash2) + " (Due to unique random salting)");

        // Verify Passwords
        boolean correctMatch = matches(originalPassword, hash1);
        boolean wrongMatch = matches("WrongPassword123", hash1);

        System.out.println("4. Verify Correct Password: " + correctMatch + " (Expected: true)");
        System.out.println("5. Verify Wrong Password:   " + wrongMatch + " (Expected: false)");

        if (correctMatch && !wrongMatch) {
            System.out.println("\n[SUCCESS] PasswordUtil security and verification passed!");
        } else {
            System.err.println("\n[FAILURE] PasswordUtil verification failed.");
        }
    }
}
