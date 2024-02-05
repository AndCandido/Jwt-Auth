package io.github.AndCandido.jwtauth.dtos.res;

import lombok.Builder;

@Builder
public record AuthenticationResponseDto(
    String token
) {
}
