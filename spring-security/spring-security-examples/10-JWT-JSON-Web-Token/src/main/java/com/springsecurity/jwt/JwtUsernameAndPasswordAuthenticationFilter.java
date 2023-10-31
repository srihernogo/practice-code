package com.springsecurity.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

@AllArgsConstructor
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    // This Class is to verify the credentials.
    // Spring Security does it by default in UsernamePasswordAuthenticationFilter.
    // But we can extend the UsernamePasswordAuthenticationFilter class and have our own implementation.

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),   // Username is the Principal
                    authenticationRequest.getPassword()    // Password is Credential
            );

            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

            // Explanation:
            // Extracted the Username and Password from the Request and stored it in UsernameAndPasswordAuthenticationRequest.
            // Used UsernamePasswordAuthenticationToken Class from Authentication Interface to set the Credentials to the Authentication.
            // Then, authenticating the credentials using authenticationManager.authenticate(authentication).
            // If the Username and Password is correct, then the request is authenticated.
            // Returning the authentication as response.
        }
        catch(IOException e) {
            throw new RuntimeException(e);
        }
    }

    // NOTE: successfulAuthentication() method will be invoked after the attemptAuthentication() method is Successful!
    // If attemptAuthentication() method fails, successfulAuthentication() will never be executed.

    // How it works ?
    // Client sends credentials (Username and Password) to the Server.             - Fetching Credentials from Request in above method.
    // Server validates the credentials and Creates and Signs the Token.           - Validation happens in the above method. Creating and Signing happens in the below method.
    // Server sends the Token to the Client.                                                        - The Created and Signed token is sent in the Response Header in the below method.
    // From next time, the Client sends only the Token in each request.             - Once we get the Token after Logging in, we can use it in subsequent requests.
    // Server validates the Token.                                                                       - JWT Implementation will validate the Token.

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) {

        // In this method, we are creating a Jwt Token and sending it to the Client (In Response).

        String jwtToken = Jwts.builder()
                .setSubject(authResult.getName())
                // Setting the Subject from authResult. This will be the Username (Jack/Jill/Tom etc.).

                .claim("authorities", authResult.getAuthorities())
                // This is like a Body of the Token. Claim is similar to Body.

                .setIssuedAt(new Date())
                // The time when the Token is issued.

                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())))
                // Setting the expiration time of the Token. Set to 2 weeks. Sql Date has to be imported here.

                .signWith(secretKey)
                // Signing the Token. The Key must be long to be more secure. So, appended "Secure" multiple times.

                .compact();
                // Compacting it into its final String form. A signed JWT is called a 'JWS'.

        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + jwtToken);
        // Added the Jwt Token to the Response Header.
        // We can find the Token in the Postman's Response Section after hitting http://localhost:8080/login with Username and Password in the Request Body.
        // The details in the Token can be checked in the JWT Debugger Tool at https://jwt.io/
    }
}
