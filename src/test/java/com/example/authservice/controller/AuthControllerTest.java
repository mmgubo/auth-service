package com.example.authservice.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.example.authservice.config.SecurityConfig;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void me_noToken_returns401() throws Exception {
        mvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_withValidJwt_returns200() throws Exception {
        mvc.perform(get("/api/auth/me")
                .with(jwt()
                        .jwt(builder -> builder
                                .subject("user-uuid-123")
                                .claim("preferred_username", "alice")
                                .claim("email", "alice@example.com")
                                .claim("given_name", "Alice")
                                .claim("family_name", "Smith"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.preferredUsername").value("alice"))
                .andExpect(jsonPath("$.email").value("alice@example.com"));
    }

    @Test
    void tokenInfo_withValidJwt_returnsClaimsMap() throws Exception {
        mvc.perform(get("/api/auth/token-info")
                .with(jwt()
                        .jwt(builder -> builder
                                .subject("user-uuid-123")
                                .claim("preferred_username", "alice"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("user-uuid-123"));
    }
}
