package com.example.authservice.controller;

import com.example.authservice.model.TokenResponse;
import com.example.authservice.service.KeycloakTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestClientResponseException;

import com.example.authservice.config.SecurityConfig;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
class TokenControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    KeycloakTokenService keycloakTokenService;

    @Test
    void refresh_validToken_returns200WithTokenPair() throws Exception {
        TokenResponse mockResponse = new TokenResponse(
                "new-access-token", "new-refresh-token", "Bearer", 300L, 1800L);

        when(keycloakTokenService.refresh(anyString())).thenReturn(mockResponse);

        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"valid-refresh-token\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("new-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("new-refresh-token"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(300));
    }

    @Test
    void refresh_missingRefreshToken_returns400() throws Exception {
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void refresh_noBody_returns400() throws Exception {
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void refresh_keycloakRejectsToken_returns401() throws Exception {
        when(keycloakTokenService.refresh(anyString()))
                .thenThrow(new org.springframework.web.client.HttpClientErrorException(
                        org.springframework.http.HttpStatus.BAD_REQUEST, "invalid_grant"));

        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"expired-token\"}"))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------------------------------
    // Logout
    // -------------------------------------------------------------------------

    @Test
    void logout_withValidToken_returns204() throws Exception {
        doNothing().when(keycloakTokenService).logout(anyString());

        mvc.perform(post("/api/auth/logout")
                        .with(jwt())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"valid-refresh-token\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void logout_missingRefreshToken_returns400() throws Exception {
        mvc.perform(post("/api/auth/logout")
                        .with(jwt())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void logout_noToken_returns401() throws Exception {
        mvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"valid-refresh-token\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_keycloakRejects_returns401() throws Exception {
        doThrow(new org.springframework.web.client.HttpClientErrorException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "invalid_token"))
                .when(keycloakTokenService).logout(anyString());

        mvc.perform(post("/api/auth/logout")
                        .with(jwt())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"bad-refresh-token\"}"))
                .andExpect(status().isUnauthorized());
    }
}
