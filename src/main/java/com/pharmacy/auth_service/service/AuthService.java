package com.pharmacy.auth_service.service;

import com.pharmacy.auth_service.dto.AuthRequest;
import com.pharmacy.auth_service.dto.AuthResponse;
import com.pharmacy.auth_service.dto.RegisterRequest;
import com.pharmacy.auth_service.entity.User;
import com.pharmacy.auth_service.entity.VerificationToken;
import com.pharmacy.auth_service.repository.UserRepository;
import com.pharmacy.auth_service.repository.VerificationTokenRepository;
import com.pharmacy.auth_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            logger.warn("Attempted registration with existing email: {}", request.getEmail());
            throw new IllegalStateException("User already exists with this email");
        }

        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .isEmailVerified(false)
                .build();

        userRepository.save(user);
        logger.info("User registered successfully: {}", user.getEmail());

        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(1))
                .build();

        tokenRepository.save(verificationToken);
        emailService.sendVerificationEmail(user.getEmail(), token);

        return new AuthResponse("Registered successfully. Check your email to verify your account.");
    }

    public String verifyToken(String token) {
        VerificationToken vt = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (vt.getExpiryDate().isBefore(LocalDateTime.now())) {
            logger.warn("Verification token expired: {}", token);
            return "Verification token has expired.";
        }

        User user = vt.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);
        tokenRepository.delete(vt);

        logger.info("Email verified successfully for user: {}", user.getEmail());
        return "Email verified successfully!";
    }

    public AuthResponse authenticate(AuthRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        if (!user.isEmailVerified()) {
            logger.warn("User attempted login without verifying email: {}", request.getEmail());
            throw new RuntimeException("Please verify your email before logging in.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            logger.warn("Invalid password attempt for email: {}", request.getEmail());
            throw new BadCredentialsException("Invalid password");
        }

        logger.info("User authenticated successfully: {}", request.getEmail());
        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token);
    }
}
