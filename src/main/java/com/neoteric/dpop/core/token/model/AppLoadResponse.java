package com.neoteric.dpop.core.token.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppLoadResponse {
    @JsonProperty("token")
    private String token;
}
