package ru.chavkin.em.keycloakdemo.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignUpRequest(
        @NotBlank
        String username,

        @NotBlank
        @Size(min = 6)
        String password,

        @NotBlank
        String role
) {
}
