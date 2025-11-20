package ru.chavkin.em.keycloakdemo.service;

import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class KeycloakRoleService {

    private final Keycloak keycloak;

    public List<String> getAllRoleNames(String realm) {
        return keycloak.realm(realm)
                .roles()
                .list()
                .stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
    }

    public boolean roleExists(String realm, String roleName) {
        List<String> roleNames = getAllRoleNames(realm);
        return roleNames.stream()
                .anyMatch(role -> role.equalsIgnoreCase(roleName));  // Игнорируем регистр для удобства
    }
}