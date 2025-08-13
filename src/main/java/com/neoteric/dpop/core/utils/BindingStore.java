package com.neoteric.dpop.core.utils;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class BindingStore {
    private final Map<String, String> tokenToJkt = new ConcurrentHashMap<>();
    private final Map<String, Instant> jtiSeen = new ConcurrentHashMap<>();

    public void bind(String token, String jkt) { tokenToJkt.put(token, jkt); }
    public String getJkt(String token) { return tokenToJkt.get(token); }

    public boolean rememberJti(String jti, long ttlSeconds) {
        Instant now = Instant.now();
        jtiSeen.entrySet().removeIf(e -> e.getValue().isBefore(now));
        if (jtiSeen.containsKey(jti)) return false;
        jtiSeen.put(jti, now.plusSeconds(ttlSeconds));
        return true;
    }

    public static String newToken() { return "at_" + UUID.randomUUID(); }
}
