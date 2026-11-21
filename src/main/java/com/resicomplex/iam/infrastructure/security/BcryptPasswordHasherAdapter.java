package com.resicomplex.iam.infrastructure.security;

import com.resicomplex.iam.domain.port.out.PasswordHasherPort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BcryptPasswordHasherAdapter implements PasswordHasherPort {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    @Override
    public String hash(String rawSecret) {
        return encoder.encode(rawSecret);
    }

    @Override
    public boolean matches(String rawSecret, String encodedHash) {
        if (rawSecret == null || encodedHash == null) {
            return false;
        }
        return encoder.matches(rawSecret, encodedHash);
    }
}
