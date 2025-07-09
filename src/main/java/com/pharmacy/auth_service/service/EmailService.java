package com.pharmacy.auth_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendVerificationEmail(String to, String token) {
        String subject = "Verify your email";
        String verificationUrl = "http://localhost:8081/api/auth/verify?token=" + token;
        String message = "Click the link below to verify your email:\n" + verificationUrl;

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setFrom("faisallatif8979@gmail.com"); // same as spring.mail.username
        mailMessage.setTo(to);
        mailMessage.setSubject(subject);
        mailMessage.setText(message);

        mailSender.send(mailMessage);
        System.out.println("Verification email sent to " + to);
    }

    public void sendPasswordResetEmail(String to, String token) {
        String url = "http://localhost:8081/api/auth/reset-password?token=" + token;
        String body = "Click this link to reset your password: " + url;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Reset Password");
        message.setText(body);
        mailSender.send(message);
    }
}
