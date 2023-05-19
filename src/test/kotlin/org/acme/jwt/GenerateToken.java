package org.acme.jwt;

import io.smallrye.jwt.build.Jwt;
import org.eclipse.microprofile.jwt.Claims;

import java.util.Arrays;
import java.util.HashSet;

/**
 * A simple utility class to generate and print a JWT token string to stdout.
 */
public class GenerateToken {
    /**
     * Generate JWT token
     */
    public static void main(String[] args) {
        String token = Jwt.issuer("https://example.com/issuer")
                .upn("jdoe@quarkus.io")
                .groups(new HashSet<>(Arrays.asList("User", "Admin")))
                .claim(Claims.birthdate.name(), "2001-07-13")
                .sign();
        System.out.println(token);
    }
}
