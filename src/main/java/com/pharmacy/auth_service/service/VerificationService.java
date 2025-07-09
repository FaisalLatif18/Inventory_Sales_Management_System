package com.pharmacy.auth_service.service;

import com.pharmacy.auth_service.entity.VerificationToken;
import com.pharmacy.auth_service.repository.VerificationTokenRepository;
import com.pharmacy.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class VerificationService {

    private final VerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Transactional
    public boolean verifyToken(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElse(null);

        if (verificationToken == null) {
            return false;
        }

        // Check expiry
        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            return false;
        }

        // Mark user as verified
        var user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        // Delete token (or mark it used)
        tokenRepository.delete(verificationToken);

        return true;
    }
}
