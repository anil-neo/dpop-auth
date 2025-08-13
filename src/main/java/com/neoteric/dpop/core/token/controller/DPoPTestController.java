package com.neoteric.dpop.core.token.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController

public class DPoPTestController {

    @GetMapping("/api/protected/test-dpop")
    public Map<String, Object> testDpop() {
        return Map.of(
                "status", "OK",
                "message", "DPoP verification passed!",
                "timestamp", Instant.now().toString()
        );
    }
}
