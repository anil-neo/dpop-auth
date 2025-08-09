package com.neoteric.dpop.core.token.controller;


import com.neoteric.dpop.core.token.model.AppLoadResponse;
import com.neoteric.dpop.core.token.model.ClientDetails;
import com.neoteric.dpop.core.token.model.Token;
import com.neoteric.dpop.core.token.model.ValidationRequest;
import com.neoteric.dpop.core.token.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/neoteric")
@Slf4j
public class TokenController {

    @Value("${neoteric.jwt-app.client-id}")
    private String clientId;
    @Value("${neoteric.jwt-app.secret}")
    private String secretKey;
    @Value("${neoteric.jwt-app.type}")
    private String type;
    @Value("${neoteric.jwt-dashboard.client-id}")
    private String dashboardClientId;
    @Value("${neoteric.jwt-dashboard.secret}")
    private String dashboardKey;
    @Value("${neoteric.jwt-dashboard.type}")
    private String dashboardType;

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping(value = "/generate-token", consumes = "application/json")
    public ResponseEntity<Token> generateToken(@RequestBody ClientDetails clientDetails) {
        log.info("Entering generateToken generating the token for the web  request={}", clientDetails);
        Token token = tokenService.generateToken(clientDetails);
        return ResponseEntity.ok(token);
    }

    @GetMapping(value = "/generateDeviceToken", consumes = "application/json")
    public ResponseEntity<Token> generateDeviceToken() {
        log.info("Entering generateDeviceToken : generating the token for the mobile-app");
        ClientDetails clientDetails = new ClientDetails();
        clientDetails.setClientSecret(secretKey);
        clientDetails.setClientId(clientId);
        // Assuming UserDetails is retrieved from SecurityContext or created manually
        Token token = tokenService.generateToken(clientDetails);
        return ResponseEntity.ok(token);
    }

    @PostMapping(value = "/validate-app-token", consumes = "application/json")
    public ResponseEntity<AppLoadResponse> validateToken(@RequestBody ValidationRequest validationRequest) {
        log.info("Entering validateToken: validating the mobile-app token for the request={},userId={}",
                validationRequest, validationRequest.getUserId());
        ClientDetails clientDetails = new ClientDetails();
        clientDetails.setClientSecret(secretKey);
        clientDetails.setClientId(clientId);
        clientDetails.setType(type);

        validationRequest.setClientDetails(clientDetails);
        String token = tokenService.validateAndRefreshToken(validationRequest);
        AppLoadResponse appLoadResponse = new AppLoadResponse();
        appLoadResponse.setToken(token);
        return ResponseEntity.ok(appLoadResponse);
    }

//
//    @PostMapping(value = "/validate-web-token", consumes = "application/json")
//    public ResponseEntity<ApiResponse<AppLoadResponse>> validateWebToken(@RequestBody ValidationRequest validationRequest) {
//        log.info("Entering validateWebToken: validating the web token for the request={}",
//                validationRequest);
//        ClientDetails clientDetails = new ClientDetails();
//        clientDetails.setClientSecret(dashboardKey);
//        clientDetails.setClientId(dashboardClientId);
//        clientDetails.setType(dashboardType);
//        validationRequest.setClientDetails(clientDetails);
//        ApiResponse<AppLoadResponse> apiResponse = tokenService.tokenValidation(validationRequest);
//        return ResponseEntity.ok(apiResponse);
//    }

}



