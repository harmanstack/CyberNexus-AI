package com.cybernexus.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PasswordUtil (BCrypt password hashing and matching).
 * Verifies Harman's Security & Cryptographic requirements.
 */
class PasswordUtilTest {

    @Test
    @DisplayName("Should successfully hash and match a valid password")
    void testHashThenMatch() {
        String rawPassword = "CorrectHorseBattery99!";
        String hash = PasswordUtil.hash(rawPassword);

        assertNotNull(hash);
        assertEquals(60, hash.length(), "BCrypt hash must be exactly 60 characters long");
        assertTrue(PasswordUtil.matches(rawPassword, hash), "Matching correct password must return true");
        assertFalse(PasswordUtil.matches("wrong-password", hash), "Matching incorrect password must return false");
    }

    @Test
    @DisplayName("Should produce different hashes for identical passwords due to salting")
    void testSaltUniqueness() {
        String password = "SamePassword123";
        String hash1 = PasswordUtil.hash(password);
        String hash2 = PasswordUtil.hash(password);

        assertNotEquals(hash1, hash2, "BCrypt must generate distinct random salts for each hash");
        assertTrue(PasswordUtil.matches(password, hash1));
        assertTrue(PasswordUtil.matches(password, hash2));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when hashing null or empty password")
    void testHashInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> PasswordUtil.hash(null));
        assertThrows(IllegalArgumentException.class, () -> PasswordUtil.hash("   "));
    }

    @Test
    @DisplayName("Should return false safely for null or invalid stored hashes without throwing exceptions")
    void testMatchInvalidInputs() {
        assertFalse(PasswordUtil.matches("password", null));
        assertFalse(PasswordUtil.matches(null, "$2a$10$validLookingHashFormatPlaceholderHere"));
        assertFalse(PasswordUtil.matches("password", "invalid-hash-format"));
    }
}
