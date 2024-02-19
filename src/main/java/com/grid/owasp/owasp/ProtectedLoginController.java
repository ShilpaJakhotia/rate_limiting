package com.grid.owasp.owasp;


import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v2")
@Slf4j
public class ProtectedLoginController {

    private static final String SERVICE_NAME = "owaspService";

    private final CredentialsStuffingService credentialsStuffingService;

    public ProtectedLoginController(CredentialsStuffingService credentialsStuffingService) {
        this.credentialsStuffingService = credentialsStuffingService;
    }

    @PostMapping("/reset-password")//-with-ratelimit
    @RateLimiter(name = "owaspService", fallbackMethod = "owaspServiceRateLimiterFallback")
    public ResponseEntity<String> rateLimitedResetPassword(@RequestParam String userName, @RequestParam String otpCode, @RequestParam String newPassword) {
        if (CredentialsStuffingService.otpDatabase.containsKey(userName) &&
                CredentialsStuffingService.otpDatabase.get(userName).equals(otpCode)) {
            //Reset password
            CredentialsStuffingService.userDatabase.put(userName, newPassword);
            log.info("Password reset successful");
            return ResponseEntity.ok("Password reset successful");
        } else {
            log.error("Password reset did not complete successfully. OTP code did not match! Invalid OTP code");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Password reset did not complete successfully. OTP code did not match! Invalid OTP code");
        }
    }

    public ResponseEntity<String> owaspServiceRateLimiterFallback(Exception ex) {
        log.info("Too many requests received2!.....");
        return new ResponseEntity<>("Too Many Requests1234: " + ex.getMessage(), HttpStatus.TOO_MANY_REQUESTS);
    }

}
