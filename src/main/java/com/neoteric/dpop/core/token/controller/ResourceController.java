package com.neoteric.dpop.core.token.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ResourceController {
    @GetMapping("/api/hello")
    public Map<String, String> hello() {
        return Map.of("message", "🎉 Protected resource reached via DPoP");
    }
}