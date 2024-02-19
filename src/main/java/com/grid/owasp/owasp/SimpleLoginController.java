package com.grid.owasp.owasp;


import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/v1")
@Slf4j
public class SimpleLoginController {

    private static final String SERVICE_NAME = "owaspService";

    private final CredentialsStuffingService credentialsStuffingService; // initialized through constructor injection

    public SimpleLoginController(CredentialsStuffingService credentialsStuffingService) {
        this.credentialsStuffingService = credentialsStuffingService;
    }

    @GetMapping
    @RateLimiter(name = "owaspService", fallbackMethod = "fallback")
    public String welcomePage() {
        credentialsStuffingService.loadData();
        log.info("Received entrypoint request.");
        return "Welcome to the site.";
    }

    /*@GetMapping("/csrf-token")
    //@RateLimiter(name = SERVICE_NAME, fallbackMethod = "owaspServiceRateLimiterFallback")
    public CsrfToken csrfToken(HttpServletRequest httpServletRequest) {
        return (CsrfToken) httpServletRequest.getAttribute("_csrf");
    }*/

    @PostMapping("/reset-password")
    public ResponseEntity<String> simpleResetPassword(@RequestParam String userName, @RequestParam String otpCode, @RequestParam String newPassword) {
        log.info("Password reset request received for userName:{} otpCode:{} newPass:{}", userName, otpCode, newPassword);
        if (CredentialsStuffingService.otpDatabase.containsKey(userName) &&
                CredentialsStuffingService.otpDatabase.get(userName).equals(otpCode)) {
            log.info("User entry found, hence password reset successful");
            CredentialsStuffingService.userDatabase.put(userName, newPassword);
            return ResponseEntity.ok("Password reset successful");
        } else {
            log.info("User entry not found, hence password reset failed.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP code");
        }
    }

    @GetMapping("/generate-otp")
    public ResponseEntity<String> generateOtp(@RequestParam String userName) {
        log.info("Generate OTP request received.");
        String otp = credentialsStuffingService.generateRandomOtp();
        CredentialsStuffingService.otpDatabase.put(userName, otp);
        log.info("Generated OTP:" + otp + " for user: " + userName);
        return ResponseEntity.ok("3 digit OTP generated successfully & sent to email/SMS: (" + otp + ") for the user: " + userName);
    }

    public String fallback(Exception ex) {
        log.info("Too many requests received!.... ");
        return "Too Many Requests2: ";
    }

    @GetMapping("/userdetails")
    public ResponseEntity<String> userDetails(@RequestParam String userName) {
        log.info("GET userDetails request received for user {}.", userName);
        Optional<User> userDetails = credentialsStuffingService.getUserDetails(userName);
        if (userDetails.isPresent()) {
            String response = "Current password for UserName: " + userName + " password: " + userDetails.get().password;
            log.info(response);
            return ResponseEntity.ok(response);
        }
        log.info("No user found with userName: " + userName);
        return ResponseEntity.ok("No user found with userName: " + userName);
    }
}
