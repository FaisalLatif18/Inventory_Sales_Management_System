package com.pharmacy.auth_service.service;

import com.pharmacy.auth_service.entity.PasswordResetToken;
import com.pharmacy.auth_service.repository.VerificationTokenRepository;
import com.pharmacy.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.pharmacy.auth_service.repository.PasswordResetTokenRepository;
import com.pharmacy.auth_service.entity.User;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepo;
    private final UserRepository userRepo;
    private final EmailService emailService;

    public void createPasswordResetToken(String email) {
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found."));

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiryDate(LocalDateTime.now().plusMinutes(15))
                .build();

        tokenRepo.save(resetToken);

        emailService.sendPasswordResetEmail(user.getEmail(), token);
    }
}
