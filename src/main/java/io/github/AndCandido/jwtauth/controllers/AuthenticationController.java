package io.github.AndCandido.jwtauth.controllers;

import io.github.AndCandido.jwtauth.dtos.req.LoginRequestDto;
import io.github.AndCandido.jwtauth.dtos.req.UserRequestDto;
import io.github.AndCandido.jwtauth.dtos.res.AuthenticationResponseDto;
import io.github.AndCandido.jwtauth.services.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseDto> register(
        @RequestBody UserRequestDto userRequestDto
    ) {
        return ResponseEntity.ok(authenticationService.register(userRequestDto));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponseDto> login(
        @RequestBody LoginRequestDto loginRequestDto
    ) {
        return ResponseEntity.ok(authenticationService.login(loginRequestDto));
    }

}
