package ru.chavkin.em.keycloakdemo.service;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import ru.chavkin.em.keycloakdemo.dto.SignUpRequest;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final Keycloak keycloak;
    private final KeycloakRoleService roleService;

    @Value("${keycloak.realm}")
    private String realm;

    public String registerUser(SignUpRequest request) {
        String role = request.role().toUpperCase();

        if (!roleService.roleExists(realm, role)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Role '" + request.role() + "' does not exist in Keycloak realm '" + realm + "'");
        }

        try {
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

                    RoleRepresentation roleRep = keycloak.realm(realm).roles().get(role).toRepresentation();

                    keycloak.realm(realm)
                            .users()
                            .get(userId)
                            .roles()
                            .realmLevel()
                            .add(Collections.singletonList(roleRep));

                    log.info("User '{}' registered with role '{}' in realm '{}'", request.username(), role, realm);
                    return "User '" + request.username() + "' successfully registered with role: " + role;
                }

                if (response.getStatus() == 409) {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "User '" + request.username() + "' already exists");
                }

                String errorMsg = response.readEntity(String.class);
                log.warn("Keycloak error during user creation: {} {}", response.getStatus(), errorMsg);
                throw new ResponseStatusException(HttpStatus.valueOf(response.getStatus()), "Failed to create user: " + errorMsg);
            }
        } catch (Exception e) {
            log.error("Registration failed for user '{}' in realm '{}'", request.username(), realm, e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Registration failed: " + e.getMessage());
        }
    }
}