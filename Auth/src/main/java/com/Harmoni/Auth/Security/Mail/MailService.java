package com.Harmoni.Auth.Security.Mail;

import com.Harmoni.Auth.Security.Auth.EmailRequest;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import java.util.UUID;

@Service
public class MailService {

    @Autowired
    private JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public String sendTemporaryPassword(String email) {
        String temporaryPassword = UUID.randomUUID().toString().substring(0, 8);
        
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail); 
            message.setTo(email);
            message.setSubject("Your Temporary Password for Harmoni");
            message.setText("Welcome to Harmoni! Your temporary password is: " + temporaryPassword);
            
            mailSender.send(message);
        } catch (Exception e) {
            System.err.println("Error sending email: " + e.getMessage());
        }
        
        return temporaryPassword;
    }

    public void sendPasswordResetEmail(String email, String resetLink) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(email);
            message.setSubject("Password Reset Request - Harmoni");
            message.setText("You requested a password reset. Please click the link below to reset your password:\n\n" 
                    + resetLink + "\n\nIf you did not request this, please ignore this email.");
            
            mailSender.send(message);
        } catch (Exception e) {
            System.err.println("Error sending password reset email: " + e.getMessage());
            throw new RuntimeException("Failed to send password reset email.");
        }
    }

    public void sendOtpEmail(String email, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Your Login OTP - Harmoni");
            String body = "<div style='font-family:sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #eee;border-radius:8px'>"
                    + "<h2 style='color:#ff8a00;margin-bottom:8px'>Harmoni Login OTP</h2>"
                    + "<p>Use the one-time password below to log in. It expires in <strong>5 minutes</strong>.</p>"
                    + "<div style='font-size:36px;font-weight:bold;letter-spacing:8px;text-align:center;"
                    + "padding:16px;background:#f9f9f9;border-radius:6px;margin:16px 0'>" + otp + "</div>"
                    + "<p style='color:#888;font-size:13px'>If you did not request this, please ignore this email.</p>"
                    + "</div>";
            helper.setText(body, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            System.err.println("Failed to send OTP email to " + email + ": " + e.getMessage());
        }
    }

    public void sendGenericEmail(EmailRequest emailRequest) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(emailRequest.getTo());
            helper.setSubject(emailRequest.getSubject());
            helper.setText(emailRequest.getBody(), true); // true indicates HTML
            mailSender.send(message);
        } catch (MessagingException e) {
            System.err.println("Email send failed to " + emailRequest.getTo() + ": " + e.getMessage());
            throw new RuntimeException("Failed to send email.");
        }
    }
}
