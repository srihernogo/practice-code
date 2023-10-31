package com.springsecurity.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
public class JwtTokenVerifier extends OncePerRequestFilter
{
//    This Class is to verify the JWT Token that is coming in the request.
//    We have extended OncePerRequestFilter Class.
//    The reason to extend OncePerRequestFilter Class is, this filter must be executed only once per request.
//    Sometimes Filters can be invoked more than once.

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException
    {
        String authorizationHeader = httpServletRequest.getHeader(jwtConfig.getAuthorizationHeader());

        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix()))
        {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try
        {
//            Extracting information from the Token.

            Jws<Claims> claimsJws = Jwts
                    .parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            Claims body = claimsJws.getBody();
            String username = body.getSubject();

//            The above logic can be written like below as well.

//            Jwts
//                    .parserBuilder()
//                    .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
//                    .build()
//                    .parseClaimsJws(token)
//                    .getBody()
//                    .getSubject()
//                    .equals("Joe");

            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities
                    .stream()
                    .map(map -> new SimpleGrantedAuthority(map.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        catch(JwtException e)
        {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
        // Once this Filter is executed, we are passing the Request and Response to the next Filter (If any).
        // If the above line is commented, then the Response Body will be empty.
    }
}
