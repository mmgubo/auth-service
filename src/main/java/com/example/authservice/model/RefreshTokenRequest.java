package com.example.authservice.model;

/**
 * Request body for POST /api/auth/refresh.
 */
public record RefreshTokenRequest(String refreshToken) {}
