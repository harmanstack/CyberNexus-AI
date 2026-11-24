package com.cybernexus.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the User domain model.
 * Verifies Harman's OOP Encapsulation and Data Integrity.
 */
class UserTest {

    @Test
    @DisplayName("Should correctly encapsulate and return User properties")
    void testUserEncapsulation() {
        LocalDateTime now = LocalDateTime.now();
        User user = new User(10, "Harman", "harman@cybernexus.com", "$2a$10$hashvalue", "admin", now);

        assertEquals(10, user.getId());
        assertEquals(10, user.getUserId());
        assertEquals("Harman", user.getName());
        assertEquals("Harman", user.getUsername());
        assertEquals("harman@cybernexus.com", user.getEmail());
        assertEquals("$2a$10$hashvalue", user.getPasswordHash());
        assertEquals("admin", user.getRole());
        assertTrue(user.isAdmin());
        assertEquals(now, user.getCreatedAt());
    }

    @Test
    @DisplayName("Should detect non-admin role correctly")
    void testStandardUserRole() {
        User user = new User("JohnDoe", "john@example.com", "$2a$10$hash", "user");
        assertFalse(user.isAdmin());
        assertEquals("user", user.getRole());
    }

    @Test
    @DisplayName("toString() should protect sensitive password hashes")
    void testToStringMasksPasswordHash() {
        User user = new User(1, "TestUser", "test@domain.com", "$2a$10$secretHashString", "user", LocalDateTime.now());
        String str = user.toString();

        assertTrue(str.contains("[PROTECTED]"), "toString must mask password hash");
        assertFalse(str.contains("secretHashString"), "toString must NOT contain real hash");
    }
}
