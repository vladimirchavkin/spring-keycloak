package ru.chavkin.em.keycloakdemo.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.chavkin.em.keycloakdemo.dto.SignUpRequest;
import ru.chavkin.em.keycloakdemo.service.KeycloakService;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakService keycloakService;

    @PostMapping("/register")
    public String register(@Valid @RequestBody SignUpRequest request) {
        return keycloakService.registerUser(request);
    }
}