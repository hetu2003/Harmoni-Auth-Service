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

    /**
     * Generates a random temporary password and sends it to the user's email.
     *
     * @param email The user's email address.
     * @return The generated temporary password.
     */
    public String sendTemporaryPassword(String email) {
        String temporaryPassword = UUID.randomUUID().toString().substring(0, 8);
        
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("no-reply@harmoni.com"); // You can use your email here or a no-reply address
            message.setTo(email);
            message.setSubject("Your Temporary Password for Harmoni");
            message.setText("Welcome to Harmoni! Your temporary password is: " + temporaryPassword);
            
            mailSender.send(message);
        } catch (Exception e) {
            // Log the exception or handle it as needed
            // For now, we'll print to console to avoid crashing the registration process
            System.err.println("Error sending email: " + e.getMessage());
        }

        return temporaryPassword;
    }
}