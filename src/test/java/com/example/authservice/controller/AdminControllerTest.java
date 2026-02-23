package com.example.authservice.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.example.authservice.config.SecurityConfig;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AdminController.class)
@Import(SecurityConfig.class)
class AdminControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void dashboard_noToken_returns401() throws Exception {
        mvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void dashboard_withUserRole_returns403() throws Exception {
        mvc.perform(get("/api/admin/dashboard")
                .with(jwt().authorities(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void dashboard_withAdminRole_returns200() throws Exception {
        mvc.perform(get("/api/admin/dashboard")
                .with(jwt()
                        .jwt(b -> b.claim("preferred_username", "carol"))
                        .authorities(
                                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.adminUser").value("carol"));
    }
}
