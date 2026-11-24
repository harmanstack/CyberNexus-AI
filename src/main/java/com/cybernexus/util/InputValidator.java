package com.cybernexus.util;

import java.util.regex.Pattern;

/** Shared checks for menu input, emails, and URLs. */
public final class InputValidator {
    private static final Pattern EMAIL = Pattern.compile(
            "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern URL = Pattern.compile(
            "^(https?://).+$", Pattern.CASE_INSENSITIVE);

    private InputValidator() {
    }

    public static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    public static String requireText(String value, String fieldName) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return value.trim();
    }

    public static String requireUsername(String username) {
        String trimmed = requireText(username, "Username");
        if (trimmed.length() < 3) {
            throw new IllegalArgumentException("Username must be at least 3 characters long");
        }
        return trimmed;
    }

    public static String requirePassword(String password) {
        String trimmed = requireText(password, "Password");
        if (trimmed.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        return trimmed;
    }

    public static boolean isValidEmail(String email) {
        return email != null && EMAIL.matcher(email.trim()).matches();
    }

    public static String requireEmail(String email) {
        if (!isValidEmail(email)) {
            throw new IllegalArgumentException("A valid email is required");
        }
        return email.trim().toLowerCase();
    }

    public static boolean looksLikeUrl(String value) {
        if (isBlank(value)) {
            return false;
        }
        String trimmed = value.trim();
        return URL.matcher(trimmed).matches() || trimmed.contains(".");
    }

    public static String requireUrl(String value) {
        String trimmed = requireText(value, "URL");
        if (!looksLikeUrl(trimmed)) {
            throw new IllegalArgumentException("Enter a URL such as https://example.com/login");
        }
        return trimmed;
    }

    public static int requireMenuChoice(String raw, int min, int max) {
        if (isBlank(raw)) {
            throw new IllegalArgumentException("Please enter a menu number");
        }
        try {
            int choice = Integer.parseInt(raw.trim());
            if (choice < min || choice > max) {
                throw new IllegalArgumentException("Choose a number between " + min + " and " + max);
            }
            return choice;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Menu choice must be a number");
        }
    }
}
