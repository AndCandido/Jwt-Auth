package io.github.AndCandido.jwtauth.dtos.req;

import lombok.Builder;

@Builder
public record LoginRequestDto(
    String username,
    String password
) {
}
