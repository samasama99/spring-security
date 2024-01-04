package org.samasama.jwt.auth;

public record AuthenticationRequest(String email, String password) {
}
