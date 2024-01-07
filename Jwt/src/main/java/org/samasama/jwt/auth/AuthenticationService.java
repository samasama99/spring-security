package org.samasama.jwt.auth;

import lombok.RequiredArgsConstructor;
import org.samasama.jwt.config.JwtService;
import org.samasama.jwt.token.Token;
import org.samasama.jwt.token.TokenRepository;
import org.samasama.jwt.token.TokenType;
import org.samasama.jwt.user.Role;
import org.samasama.jwt.user.User;
import org.samasama.jwt.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;

@Service
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/")
public class AuthenticationService {

    final private UserRepository userRepository;
    final private TokenRepository tokenRepository;
    final private PasswordEncoder passwordEncoder;
    final private AuthenticationManager authenticationManager;
    final private JwtService jwtService;

    private Token saveUserToken(User user, String jwtToken) {
        tokenRepository.save(
                Token.builder()
                        .user(user)
                        .token(jwtToken)
                        .tokenType(TokenType.BEARER)
                        .expired(false)
                        .revoked(false)
                        .build();
        )
    }


    private void revokeAllUserTokens(User user) {
        var validTokensByUser = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validTokensByUser.isEmpty())
            return;
        validTokensByUser.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validTokensByUser);
    }

    public AuthenticationResponse register(RegisterRequest request) {
        var user = buildUserFromRequest(request);
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var token = saveUserToken(savedUser, jwtToken);
        tokenRepository.save(token);
        return new AuthenticationResponse(jwtToken);
    }

    private User buildUserFromRequest(RegisterRequest request) {
        return User.builder()
                .fName(request.fName())
                .lName(request.lName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        var user = userRepository.findByEmail(request.email()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return new AuthenticationResponse(jwtToken);
    }
}
