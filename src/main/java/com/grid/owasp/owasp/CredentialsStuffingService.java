package com.grid.owasp.owasp;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

@Service
@Slf4j
public class CredentialsStuffingService {

    public static final Map<String, String> userDatabase = new HashMap<>();
    public static final Map<String, String> otpDatabase = new HashMap<>();

    @SneakyThrows
    public void loadData() {
        userDatabase.put("user1", "passuser1");
        userDatabase.put("user2", "passuser2");
        userDatabase.put("sganapa@griddynamics.com", "passsganapa");
        userDatabase.put("santoshganapa@gmail.com", "passsantoshganapa");
        loadOtpCodesFromFile();
    }

    private void loadOtpCodesFromFile() {
        if (otpDatabase.isEmpty()) {
            log.info("Load user-otp codes from file.");
            try (BufferedReader br = new BufferedReader(new FileReader("src/main/resources/3digitotpcodes.txt"))) {
                String code;
                while ((code = br.readLine()) != null) {
                    String[] singleMapping = code.split(",");
                    otpDatabase.put(singleMapping[0], singleMapping[1]);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Generate 3-digit OTP code
     *
     * @return String containing 3 digit OTP code
     */
    public String generateRandomOtp() {
        Random random = new Random();
        int otp = random.nextInt(900) + 100;
        return String.valueOf(otp);
    }

    public Optional<User> getUserDetails(String userName) {
        if (userDatabase.containsKey(userName)) {
            return Optional.of(User.builder().userName(userName).password(userDatabase.get(userName)).build());
        } else return Optional.empty();
    }

}
