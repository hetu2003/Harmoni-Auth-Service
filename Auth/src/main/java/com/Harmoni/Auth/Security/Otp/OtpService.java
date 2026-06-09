package com.Harmoni.Auth.Security.Otp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {

    private static final String OTP_KEY_PREFIX = "otp:";
    private static final long OTP_TTL_MINUTES = 5;
    private static final int OTP_LENGTH = 6;

    @Autowired
    private StringRedisTemplate redisTemplate;

    public String generateAndStoreOtp(String email) {
        String otp = generateOtp();
        String key = OTP_KEY_PREFIX + email.toLowerCase();
        redisTemplate.opsForValue().set(key, otp, OTP_TTL_MINUTES, TimeUnit.MINUTES);
        return otp;
    }

    public boolean verifyOtp(String email, String otp) {
        String key = OTP_KEY_PREFIX + email.toLowerCase();
        String storedOtp = redisTemplate.opsForValue().get(key);
        if (storedOtp != null && storedOtp.equals(otp)) {
            redisTemplate.delete(key);
            return true;
        }
        return false;
    }

    public boolean hasActiveOtp(String email) {
        String key = OTP_KEY_PREFIX + email.toLowerCase();
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otpValue = 100000 + random.nextInt(900000);
        return String.valueOf(otpValue);
    }
}
