package com.example.authservice.model;

import java.util.List;

/**
 * Represents the authenticated user's identity extracted from the Keycloak JWT.
 */
public record UserInfo(
        String sub,
        String preferredUsername,
        String email,
        String firstName,
        String lastName,
        List<String> roles
) {}
