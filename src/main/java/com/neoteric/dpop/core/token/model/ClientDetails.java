package com.neoteric.dpop.core.token.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClientDetails {
    @JsonProperty("clientId")
    private String clientId;
    @JsonProperty("clientSecret")
    private String clientSecret;
    @JsonProperty("type")
    private String type;
}
