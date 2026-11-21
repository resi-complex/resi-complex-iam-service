package com.resicomplex.iam.infrastructure.security;

import com.resicomplex.iam.domain.exception.IamDomainException;
import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.port.out.TokenProviderPort;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Dependency-free HS256 JWT implementation using Java 25 native javax.crypto.Mac.
 * Emits standard RFC 7519 claims (sub, email, role, roles, permissions, iat, exp, jti)
 * required by 00-governance/security-policy.md and ADR-006.
 */
@Component
public class Hs256JwtTokenProviderAdapter implements TokenProviderPort {

    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String HEADER_JSON = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final byte[] secretBytes;
    private final long accessExpirationSeconds;

    public Hs256JwtTokenProviderAdapter(
        @Value("${iam.jwt.secret:resicomplex-local-dev-hs256-signing-secret-key-at-least-256-bits-long-2026}") String secret,
        @Value("${iam.jwt.access-expiration-seconds:3600}") long accessExpirationSeconds
    ) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 256 bits (32 bytes)");
        }
        this.secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.accessExpirationSeconds = accessExpirationSeconds;
    }

    @Override
    public String generateAccessToken(UserAccount user, Instant now) {
        long iat = now.getEpochSecond();
        long exp = iat + accessExpirationSeconds;
        String jti = UUID.randomUUID().toString();
        UserRole role = user.role();
        String permissionsJson = toJsonArray(role.getPermissions());

        String payloadJson = "{"
            + "\"sub\":\"" + escapeJson(user.id()) + "\","
            + "\"email\":\"" + escapeJson(user.email()) + "\","
            + "\"role\":\"" + role.name() + "\","
            + "\"roles\":[\"" + role.name() + "\"],"
            + "\"permissions\":" + permissionsJson + ","
            + "\"iat\":" + iat + ","
            + "\"exp\":" + exp + ","
            + "\"jti\":\"" + jti + "\""
            + "}";

        String encodedHeader = URL_ENCODER.encodeToString(HEADER_JSON.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = URL_ENCODER.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = encodedHeader + "." + encodedPayload;
        String signature = sign(signingInput);
        return signingInput + "." + signature;
    }

    @Override
    public VerifiedJwtClaims verifyAccessToken(String token, Instant now) {
        if (token == null || token.isBlank()) {
            throw new IamDomainException("UNAUTHORIZED", "Missing bearer token", 401);
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IamDomainException("INVALID_TOKEN", "Malformed JWT token", 401);
        }

        String signingInput = parts[0] + "." + parts[1];
        String expectedSignature = sign(signingInput);
        if (!MessageDigest.isEqual(
            expectedSignature.getBytes(StandardCharsets.UTF_8),
            parts[2].getBytes(StandardCharsets.UTF_8)
        )) {
            throw new IamDomainException("INVALID_TOKEN_SIGNATURE", "Invalid JWT signature", 401);
        }

        String payloadJson;
        try {
            payloadJson = new String(URL_DECODER.decode(parts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw new IamDomainException("INVALID_TOKEN", "Invalid Base64 payload in JWT", 401);
        }

        long exp = extractLongClaim(payloadJson, "exp");
        long iat = extractLongClaim(payloadJson, "iat");
        if (now.getEpochSecond() >= exp) {
            throw new IamDomainException("TOKEN_EXPIRED", "Access token has expired", 401);
        }

        String sub = extractStringClaim(payloadJson, "sub");
        String email = extractStringClaim(payloadJson, "email");
        String roleName = extractStringClaim(payloadJson, "role");
        String jti = extractStringClaim(payloadJson, "jti");
        UserRole role = UserRole.fromValue(roleName);

        return new VerifiedJwtClaims(
            sub,
            email,
            role.name(),
            role.getPermissions(),
            jti,
            Instant.ofEpochSecond(iat),
            Instant.ofEpochSecond(exp)
        );
    }

    @Override
    public long getAccessExpirationSeconds() {
        return accessExpirationSeconds;
    }

    private String sign(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(secretBytes, HMAC_ALGO));
            byte[] rawHmac = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            return URL_ENCODER.encodeToString(rawHmac);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to compute HMAC-SHA256 signature", ex);
        }
    }

    private static String toJsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(escapeJson(items.get(i))).append('"');
        }
        sb.append(']');
        return sb.toString();
    }

    private static String escapeJson(String input) {
        return input == null ? "" : input.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String extractStringClaim(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            throw new IamDomainException("INVALID_TOKEN", "Missing claim: " + key, 401);
        }
        return matcher.group(1);
    }

    private static long extractLongClaim(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            throw new IamDomainException("INVALID_TOKEN", "Missing numeric claim: " + key, 401);
        }
        return Long.parseLong(matcher.group(1));
    }
}
