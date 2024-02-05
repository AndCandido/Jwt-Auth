package io.github.AndCandido.jwtauth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/private")
public class DemoController {

    @GetMapping
    public String privateRoute() {
        return "This is a private route";
    }

}
