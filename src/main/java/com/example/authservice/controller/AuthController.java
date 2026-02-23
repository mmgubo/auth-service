package com.example.authservice.controller;

import com.example.authservice.model.UserInfo;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Exposes the current user's identity and raw token claims.
 * All endpoints here require a valid Bearer token.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * Returns a structured view of the authenticated user's identity.
     * GET /api/auth/me
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfo> me(JwtAuthenticationToken auth) {
        Jwt jwt = auth.getToken();
        return ResponseEntity.ok(buildUserInfo(jwt, auth));
    }

    /**
     * Returns the raw JWT claims exactly as they arrived from Keycloak.
     * Useful for debugging the token structure.
     * GET /api/auth/token-info
     */
    @GetMapping("/token-info")
    public ResponseEntity<Map<String, Object>> tokenInfo(JwtAuthenticationToken auth) {
        return ResponseEntity.ok(auth.getToken().getClaims());
    }

    /**
     * Returns the principal name (preferred_username).
     * GET /api/auth/principal
     */
    @GetMapping("/principal")
    public ResponseEntity<Map<String, String>> principal(Principal principal) {
        return ResponseEntity.ok(Map.of("principal", principal.getName()));
    }

    // -------------------------------------------------------------------------

    private UserInfo buildUserInfo(Jwt jwt, Authentication auth) {
        // Collect roles from the Security context (already mapped by the JWT converter)
        List<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring(5))          // strip "ROLE_" prefix
                .toList();

        return new UserInfo(
                jwt.getSubject(),
                jwt.getClaimAsString("preferred_username"),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("given_name"),
                jwt.getClaimAsString("family_name"),
                roles
        );
    }
}
