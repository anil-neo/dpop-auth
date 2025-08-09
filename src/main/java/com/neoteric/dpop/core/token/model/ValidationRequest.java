package com.neoteric.dpop.core.token.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ValidationRequest {
    @JsonProperty("token")
    private String token;
    @JsonProperty("userId")
    private String userId;
    @JsonProperty("clientDetails")
    private ClientDetails clientDetails;
}
