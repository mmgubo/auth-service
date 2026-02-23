package com.example.authservice.service;

import com.example.authservice.model.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * Delegates token operations (refresh) to the Keycloak token endpoint.
 *
 * Uses Spring 6.1 {@link RestClient} (synchronous, fluent).
 * If Keycloak returns 4xx (e.g. expired / invalid refresh token), RestClient
 * throws {@link org.springframework.web.client.RestClientResponseException},
 * which is mapped to HTTP 401 by {@link com.example.authservice.exception.GlobalExceptionHandler}.
 */
@Service
public class KeycloakTokenService {

    private final RestClient restClient;
    private final String tokenEndpoint;
    private final String clientId;

    public KeycloakTokenService(
            RestClient.Builder builder,
            @Value("${app.keycloak.auth-server-url}") String authServerUrl,
            @Value("${app.keycloak.realm}") String realm,
            @Value("${app.keycloak.client-id}") String clientId) {

        this.restClient = builder.build();
        this.tokenEndpoint = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        this.clientId = clientId;
    }

    /**
     * Exchanges a refresh token for a new token pair.
     *
     * @param refreshToken the refresh token issued by Keycloak
     * @return new {@link TokenResponse} containing a fresh access token and refresh token
     * @throws org.springframework.web.client.RestClientResponseException if Keycloak rejects the token
     */
    public TokenResponse refresh(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type",    "refresh_token");
        form.add("client_id",     clientId);
        form.add("refresh_token", refreshToken);

        Map<?, ?> body = restClient.post()
                .uri(tokenEndpoint)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        return mapToTokenResponse(body);
    }

    // -------------------------------------------------------------------------

    private TokenResponse mapToTokenResponse(Map<?, ?> map) {
        return new TokenResponse(
                (String) map.get("access_token"),
                (String) map.get("refresh_token"),
                (String) map.get("token_type"),
                ((Number) map.get("expires_in")).longValue(),
                ((Number) map.get("refresh_expires_in")).longValue()
        );
    }
}
