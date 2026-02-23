package com.example.authservice.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Token response returned by POST /api/auth/refresh.
 * Field names match Keycloak's snake_case JSON so the response is idiomatic
 * for OAuth2 clients while staying clean internally.
 */
public record TokenResponse(
        @JsonProperty("access_token")      String accessToken,
        @JsonProperty("refresh_token")     String refreshToken,
        @JsonProperty("token_type")        String tokenType,
        @JsonProperty("expires_in")        long expiresIn,
        @JsonProperty("refresh_expires_in") long refreshExpiresIn
) {}
