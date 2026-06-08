package com.Harmoni.Auth.Security.Mail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import java.util.UUID;

@Service
public class MailService {

    @Autowired
    private JavaMailSender mailSender;

    public String sendTemporaryPassword(String email) {
        String temporaryPassword = UUID.randomUUID().toString().substring(0, 8);
        
        try {
            SimpleMailMessage message = new SimpleMailMessage();
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
            message.setFrom("no-reply@harmoni.com");
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
}
