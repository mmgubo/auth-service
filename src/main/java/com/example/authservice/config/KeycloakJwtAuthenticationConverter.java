package com.example.authservice.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Converts a Keycloak-issued JWT into a Spring Security Authentication.
 *
 * Keycloak places realm-level roles under:  jwt.realm_access.roles
 * Client-level roles are under:            jwt.resource_access.<client-id>.roles
 *
 * Both sets are mapped to ROLE_<UPPERCASE_ROLE> so @PreAuthorize("hasRole('ADMIN')")
 * and SecurityConfig's hasRole() checks work as expected.
 */
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String REALM_ACCESS_CLAIM    = "realm_access";
    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
    private static final String ROLES_CLAIM           = "roles";
    private static final String PREFERRED_USERNAME    = "preferred_username";

    private final String clientId;

    public KeycloakJwtAuthenticationConverter(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                extractRealmRoles(jwt).stream(),
                extractClientRoles(jwt).stream()
        ).collect(Collectors.toSet());

        // Use preferred_username as the principal name; fall back to subject (UUID)
        String principalName = jwt.getClaimAsString(PREFERRED_USERNAME);
        if (principalName == null) {
            principalName = jwt.getSubject();
        }

        return new JwtAuthenticationToken(jwt, authorities, principalName);
    }

    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractRealmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap(REALM_ACCESS_CLAIM);
        if (realmAccess == null) return Collections.emptyList();

        List<String> roles = (List<String>) realmAccess.get(ROLES_CLAIM);
        if (roles == null) return Collections.emptyList();

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractClientRoles(Jwt jwt) {
        if (clientId == null || clientId.isBlank()) return Collections.emptyList();

        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS_CLAIM);
        if (resourceAccess == null) return Collections.emptyList();

        Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
        if (clientAccess == null) return Collections.emptyList();

        List<String> roles = (List<String>) clientAccess.get(ROLES_CLAIM);
        if (roles == null) return Collections.emptyList();

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
    }
}
