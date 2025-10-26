package ru.chavkin.em.keycloakdemo.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import ru.chavkin.em.keycloakdemo.dto.SignUpRequest;

import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.admin.client-id}")
    private String clientId;

    @Value("${keycloak.admin.client-secret}")
    private String clientSecret;

    private static final List<String> ALLOWED_ROLES = List.of("USER", "ADMIN", "MODERATOR");

    @PostMapping("/register")
    public String register(@Valid @RequestBody SignUpRequest request) {
        String role = request.role().toUpperCase();
        if (!ALLOWED_ROLES.contains(role)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Role '" + request.role() + "' not allowed. Allowed: " + ALLOWED_ROLES);
        }

        try (Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType("client_credentials")
                .build()) {
            UserRepresentation user = new UserRepresentation();
            user.setUsername(request.username());
            user.setEnabled(true);
            user.setEmailVerified(false);

            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setTemporary(false);
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(request.password());
            user.setCredentials(Collections.singletonList(credential));

            try (Response response = keycloak.realm(realm).users().create(user)) {
                if (response.getStatus() == 201) {
                    String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

                    RoleRepresentation roleRep;
                    try {
                        roleRep = keycloak.realm(realm).roles().get(role).toRepresentation();
                    } catch (jakarta.ws.rs.NotFoundException e) {
                        log.warn("Role {} not found in realm {}", role, realm);
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role '" + role + "' does not exist in Keycloak");
                    }

                    // Назначение роли
                    keycloak.realm(realm)
                            .users()
                            .get(userId)
                            .roles()
                            .realmLevel()
                            .add(Collections.singletonList(roleRep));

                    log.info("User '{}' registered with role '{}'", request.username(), role);
                    return "User '" + request.username() + "' successfully registered with role: " + role;
                }

                if (response.getStatus() == 409) {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "User '" + request.username() + "' already exists");
                }

                String errorMsg = response.readEntity(String.class);
                log.warn("Keycloak error: {} {}", response.getStatus(), errorMsg);
                throw new ResponseStatusException(HttpStatus.valueOf(response.getStatus()), "Failed to create user: " + errorMsg);
            }
        } catch (Exception e) {
            log.error("Registration failed for user {}", request.username(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Registration failed: " + e.getMessage());
        }
    }
}