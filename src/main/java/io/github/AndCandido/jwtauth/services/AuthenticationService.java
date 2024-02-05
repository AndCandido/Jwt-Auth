package io.github.AndCandido.jwtauth.services;

import io.github.AndCandido.jwtauth.dtos.req.LoginRequestDto;
import io.github.AndCandido.jwtauth.dtos.req.UserRequestDto;
import io.github.AndCandido.jwtauth.dtos.res.AuthenticationResponseDto;
import io.github.AndCandido.jwtauth.user.Role;
import io.github.AndCandido.jwtauth.user.User;
import io.github.AndCandido.jwtauth.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponseDto register(UserRequestDto userRequestDto) {
        User user = User.builder()
            .firstName(userRequestDto.firstname())
            .lastName(userRequestDto.lastname())
            .username(userRequestDto.username())
            .password(passwordEncoder.encode(userRequestDto.password()))
            .role(Role.USER)
            .build();

        userRepository.save(user);
        String token = jwtService.generateToken(user);

        return AuthenticationResponseDto.builder()
            .token(token)
            .build();
    }

    public AuthenticationResponseDto login(LoginRequestDto loginRequestDto) {
        var authToken = new UsernamePasswordAuthenticationToken(
            loginRequestDto.username(), loginRequestDto.password()
        );
        Authentication authenticate = authenticationManager.authenticate(authToken);
        String token = jwtService.generateToken((UserDetails) authenticate.getPrincipal());

        return AuthenticationResponseDto.builder()
            .token(token)
            .build();
    }
}
