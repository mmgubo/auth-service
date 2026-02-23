package com.example.authservice.controller;

import com.example.authservice.model.RefreshTokenRequest;
import com.example.authservice.model.TokenResponse;
import com.example.authservice.service.KeycloakTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Handles token lifecycle operations that don't require an existing valid JWT.
 *
 * POST /api/auth/refresh — exchanges a Keycloak refresh token for a new token pair.
 * This endpoint is intentionally unauthenticated: the caller's access token is
 * expired (or about to expire) when a refresh is needed.
 */
@RestController
@RequestMapping("/api/auth")
public class TokenController {

    private final KeycloakTokenService keycloakTokenService;

    public TokenController(KeycloakTokenService keycloakTokenService) {
        this.keycloakTokenService = keycloakTokenService;
    }

    /**
     * Refreshes an expired access token.
     *
     * <pre>
     * POST /api/auth/refresh
     * Content-Type: application/json
     *
     * { "refreshToken": "<keycloak-refresh-token>" }
     * </pre>
     *
     * Returns HTTP 200 with a new token pair on success, or HTTP 400 if
     * {@code refreshToken} is missing, or HTTP 401 if Keycloak rejects the token.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshTokenRequest request) {
        if (request.refreshToken() == null || request.refreshToken().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(keycloakTokenService.refresh(request.refreshToken()));
    }
}
