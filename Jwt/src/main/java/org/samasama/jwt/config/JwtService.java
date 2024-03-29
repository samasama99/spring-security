package org.samasama.jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    static private final String SECRET_KEY = "AeR+LZ0kjwaAwI84gPkylIMl7Mato/Cyn7WCcBiNv2H81nI42Cah3Bv0hJjhUJCwfmFyiLjWUx2QZf7G/WljDZH8OzRIrk49oLbMwYyaHtp7ojrYeSZPktxjHQvpz+yGasrgtpHkfFa47sLeZofkO1G8ipLATPrTtWohctIj1PidbLJhWJJfvWiEmuLvQ+Xy/uDFS2SHkzNG1qe8aWdyjV0q/6ykeft9Hkh8nnDHLru58jToTqwfeN4CCLcwdlhi5flkB1MbfU5c8rzHriIIyySdtGu/ZRXzo94NR/HUydN0QFCmNrsFtkeER1GiYMBHDRNaoupHSarD8tyEiKtBo+fshBM4dwxB+Wa0JEgqjD4=";

    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(
            UserDetails userDetails
    ) {
        // username is the email in this case
        return generateToken(new HashMap<>(), userDetails);

    }

    boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        // username is the email in this case
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
