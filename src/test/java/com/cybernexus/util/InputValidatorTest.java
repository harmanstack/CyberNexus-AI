package com.cybernexus.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit Test Suite for Aarchi's Terminal InputValidator.
 */
class InputValidatorTest {

    @Test
    @DisplayName("Email: Accepts standard valid email and normalizes casing")
    void testValidEmail() {
        assertTrue(InputValidator.isValidEmail("aarchi@cybernexus.com"));
        assertEquals("aarchi@cybernexus.com", InputValidator.requireEmail("  Aarchi@CyberNexus.COM "));
    }

    @Test
    @DisplayName("Email: Rejects malformed email")
    void testInvalidEmail() {
        assertFalse(InputValidator.isValidEmail("plainaddress"));
        assertFalse(InputValidator.isValidEmail("@missingusername.com"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireEmail("bademail.com"));
    }

    @Test
    @DisplayName("Menu Choices: Validates within range and rejects non-numeric or out-of-range")
    void testMenuChoiceValidation() {
        assertEquals(1, InputValidator.requireMenuChoice("1", 1, 3));
        assertEquals(2, InputValidator.requireMenuChoice(" 2 ", 1, 3));
        assertEquals(3, InputValidator.requireMenuChoice("3", 1, 3));

        // Non-numeric
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireMenuChoice("abc", 1, 3));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireMenuChoice("", 1, 3));

        // Out of bounds
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireMenuChoice("0", 1, 3));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireMenuChoice("4", 1, 3));
    }

    @Test
    @DisplayName("Username & Password: Enforces length constraints")
    void testUsernameAndPasswordConstraints() {
        assertEquals("aarchi", InputValidator.requireUsername("aarchi"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireUsername("ab"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireUsername("   "));

        assertEquals("SecurePass123", InputValidator.requirePassword("SecurePass123"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requirePassword("short"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requirePassword(""));
    }

    @Test
    @DisplayName("URL & Message: Validates URL format and text requirement")
    void testUrlAndTextValidation() {
        assertTrue(InputValidator.looksLikeUrl("https://bank.com/login"));
        assertTrue(InputValidator.looksLikeUrl("google.com"));
        assertFalse(InputValidator.looksLikeUrl("   "));

        assertEquals("https://test.com", InputValidator.requireUrl("  https://test.com "));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireUrl(""));

        assertEquals("Hello world", InputValidator.requireText("  Hello world  ", "Message"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireText("   ", "Message"));
    }
}
