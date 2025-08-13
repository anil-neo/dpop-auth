package com.neoteric.dpop.core.token.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/protected")
public class ProtectedController {
    @GetMapping("/hello")
    public Map<String, Object> hello() {
        return Map.of("ok", true, "message", "DPoP-protected resource" );
    }
}
