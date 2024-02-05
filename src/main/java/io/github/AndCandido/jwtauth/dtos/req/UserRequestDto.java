package io.github.AndCandido.jwtauth.dtos.req;

import lombok.Builder;

@Builder
public record UserRequestDto(
    String firstname,
    String lastname,
    String username,
    String password
) {
}
