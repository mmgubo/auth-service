package com.example.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Admin-only endpoints.
 *
 * Access is guarded at TWO levels:
 *   1. SecurityConfig: requestMatchers("/api/admin/**").hasRole("ADMIN")
 *   2. @PreAuthorize on each method — defence-in-depth
 *
 * Both require the caller's JWT to contain the "admin" realm role in Keycloak,
 * which is mapped to ROLE_ADMIN by KeycloakJwtAuthenticationConverter.
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")          // class-level default; all methods inherit it
public class AdminController {

    /**
     * Admin dashboard summary.
     * GET /api/admin/dashboard
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> dashboard(JwtAuthenticationToken auth) {
        return ResponseEntity.ok(Map.of(
                "message",   "Welcome to the admin dashboard",
                "adminUser", auth.getToken().getClaimAsString("preferred_username"),
                "timestamp", Instant.now().toString()
        ));
    }

    /**
     * List all users (stub — replace with real user-store lookup).
     * GET /api/admin/users
     */
    @GetMapping("/users")
    public ResponseEntity<List<Map<String, String>>> listUsers() {
        // In a real service this would query the user store / Keycloak Admin REST API
        List<Map<String, String>> users = List.of(
                Map.of("id", "1", "username", "alice", "role", "USER"),
                Map.of("id", "2", "username", "bob",   "role", "USER"),
                Map.of("id", "3", "username", "carol", "role", "ADMIN")
        );
        return ResponseEntity.ok(users);
    }

    /**
     * Show raw token claims for the current admin — useful for auditing.
     * GET /api/admin/token-audit
     */
    @GetMapping("/token-audit")
    public ResponseEntity<Map<String, Object>> tokenAudit(JwtAuthenticationToken auth) {
        return ResponseEntity.ok(auth.getToken().getClaims());
    }
}
