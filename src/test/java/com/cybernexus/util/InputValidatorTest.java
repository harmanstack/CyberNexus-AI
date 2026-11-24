package com.cybernexus.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InputValidatorTest {
    @Test
    void acceptsNormalEmail() {
        assertTrue(InputValidator.isValidEmail("student@college.edu"));
        assertEquals("student@college.edu", InputValidator.requireEmail("  Student@college.edu "));
    }

    @Test
    void rejectsBadMenuChoice() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireMenuChoice("x", 1, 3));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireMenuChoice("9", 1, 3));
    }
}
