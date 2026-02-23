package com.example.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Endpoints accessible to any authenticated user.
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    /**
     * Returns the authenticated user's profile summary.
     * GET /api/user/profile
     */
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> profile(JwtAuthenticationToken auth) {
        return ResponseEntity.ok(Map.of(
                "username", auth.getToken().getClaimAsString("preferred_username"),
                "email",    nullSafe(auth.getToken().getClaimAsString("email")),
                "roles",    auth.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList())
        ));
    }

    /**
     * A simple greeting endpoint demonstrating role-based logic in the controller.
     * GET /api/user/greet
     */
    @GetMapping("/greet")
    public ResponseEntity<String> greet(JwtAuthenticationToken auth) {
        String username = auth.getToken().getClaimAsString("preferred_username");
        return ResponseEntity.ok("Hello, " + username + "! Your token is valid.");
    }

    /**
     * Only accessible to users who have the USER role.
     * GET /api/user/restricted
     */
    @GetMapping("/restricted")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, String>> restricted(JwtAuthenticationToken auth) {
        return ResponseEntity.ok(Map.of(
                "message", "You have the USER role.",
                "subject", auth.getToken().getSubject()
        ));
    }

    // -------------------------------------------------------------------------

    private String nullSafe(String value) {
        return value != null ? value : "";
    }
}
