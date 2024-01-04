package org.samasama.jwt.auth;

public record RegisterRequest(String fName, String lName, String email, String password) {
}
