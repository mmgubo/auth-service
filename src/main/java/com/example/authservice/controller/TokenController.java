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
 * Handles token lifecycle operations.
 *
 * POST /api/auth/refresh — unauthenticated; exchanges an expired access token for a new pair.
 * POST /api/auth/logout  — authenticated; revokes the refresh token at Keycloak.
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

    /**
     * Logs the current user out by revoking their refresh token at Keycloak.
     *
     * <pre>
     * POST /api/auth/logout
     * Authorization: Bearer &lt;valid-access-token&gt;
     * Content-Type: application/json
     *
     * { "refreshToken": "&lt;keycloak-refresh-token&gt;" }
     * </pre>
     *
     * Returns HTTP 204 No Content on success.
     * Returns HTTP 400 if {@code refreshToken} is missing or blank.
     * Returns HTTP 401 if no valid Bearer token is provided.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshTokenRequest request) {
        if (request.refreshToken() == null || request.refreshToken().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        keycloakTokenService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
