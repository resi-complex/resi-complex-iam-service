package com.resicomplex.iam.domain.port.out;

public interface PasswordHasherPort {
    String hash(String rawSecret);
    boolean matches(String rawSecret, String encodedHash);
}
