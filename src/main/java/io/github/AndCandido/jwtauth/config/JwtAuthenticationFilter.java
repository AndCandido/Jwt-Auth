package io.github.AndCandido.jwtauth.config;

import io.github.AndCandido.jwtauth.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String requestAuth = request.getHeader("Authorization");

        if(requestAuth == null || !requestAuth.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = requestAuth.replace("Bearer ", "");
        String username = jwtService.extractUsername(jwt);

        Authentication securityContextAuth = SecurityContextHolder.getContext().getAuthentication();

        if(username == null && securityContextAuth != null) {
            filterChain.doFilter(request, response);
            return;
        }

        UserDetails user = userDetailsService.loadUserByUsername(username);

        if(jwtService.isValidToken(jwt, user)) {
            authorizeUser(request, user);
        }

        filterChain.doFilter(request, response);
    }

    private void authorizeUser(HttpServletRequest request, UserDetails user) {
        UsernamePasswordAuthenticationToken authToken =
            new UsernamePasswordAuthenticationToken(user.getUsername(), null,user.getAuthorities());
        authToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
