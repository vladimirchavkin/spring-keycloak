package ru.chavkin.em.keycloakdemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1")
public class DemoController {

    @GetMapping("/public")
    public String publicEndpoint() {
        log.info("Public endpoint called");
        return "Public endpoint – доступен всем.";
    }

    @GetMapping("/protected")
    public String protectedEndpoint(@AuthenticationPrincipal Jwt jwt) {
        log.info("Protected endpoint called by {}", jwt.getSubject());
        return "Protected endpoint – only authenticated users.";
    }

    @GetMapping("/admin")
    public String adminEndpoint(@AuthenticationPrincipal Jwt jwt) {
        log.info("Admin endpoint called by {}", jwt.getSubject());
        return "Admin endpoint – only ADMIN.";
    }

    @GetMapping("/user")
    public String userEndpoint(@AuthenticationPrincipal Jwt jwt) {
        log.info("User endpoint called by {}", jwt.getSubject());
        return "User endpoint – only USER.";
    }

    @GetMapping("/moderator")
    public String moderatorEndpoint(@AuthenticationPrincipal Jwt jwt) {
        log.info("Moderator endpoint called by {}", jwt.getSubject());
        return "Moderator endpoint – only MODER.";
    }
}