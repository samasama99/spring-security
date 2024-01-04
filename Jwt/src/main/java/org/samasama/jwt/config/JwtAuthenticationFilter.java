package org.samasama.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    final private JwtService jwtService;
    final private UserDetailsService userDetailsService;

    //    @Override
//    protected void doFilterInternal(
//            @NotNull HttpServletRequest request,
//            @NotNull HttpServletResponse response,
//            @NotNull FilterChain filterChain
//    ) throws ServletException, IOException {
//        Optional<String> jwtToken =
//                Optional.ofNullable(request.getHeader("Authorization"))
//                        .filter(auth -> auth.startsWith("Bearer "))
//                        .map(auth -> auth.substring(7));
//
//        if (jwtToken.isEmpty()) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        String token = jwtToken.get();
//
//        final Optional<String> userEmail = Optional.ofNullable(jwtService.extractUsername(token));
//        UserDetails userDetails = userEmail
//                .filter(u -> SecurityContextHolder.getContext().getAuthentication() == null)
//                .map(this.userDetailsService::loadUserByUsername)
//                .filter(uD -> jwtService.isTokenValid(token, uD))
//                .orElseThrow();
//
//        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);
//
//    }
    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        String bearer = "Bearer ";

        Optional.ofNullable(request.getHeader("Authorization"))
                .filter(auth -> auth.startsWith(bearer))
                .map(auth -> auth.substring(bearer.length()))
                .ifPresent(token -> processToken(token, request));

        filterChain.doFilter(request, response);
    }

    private void processToken(String token, HttpServletRequest request) {
        Optional.ofNullable(jwtService.extractUsername(token))
                .map(userDetailsService::loadUserByUsername)
                .filter(userDetails -> jwtService.isTokenValid(token, userDetails))
                .ifPresentOrElse(
                        userDetails -> authenticateUser(userDetails, request),
                        SecurityContextHolder::clearContext
                );
    }

    private void authenticateUser(UserDetails userDetails, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
//        final String authHeader = request.getHeader("Authorization");
//
//        if (authHeader == null || authHeader.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
//            return;
//        }

