package com.resicomplex.iam.infrastructure.web;

import com.resicomplex.iam.domain.exception.IamDomainException;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.ApiProblemView;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class IamErrorAdvice {

    @ExceptionHandler(IamDomainException.class)
    public ResponseEntity<ApiProblemView> onDomainError(IamDomainException ex) {
        HttpStatus code = HttpStatus.resolve(ex.getHttpStatus());
        if (code == null) {
            code = HttpStatus.BAD_REQUEST;
        }
        ApiProblemView problem = new ApiProblemView(
            "urn:resicomplex:iam:" + ex.getErrorCode().toLowerCase(),
            code.getReasonPhrase(),
            code.value(),
            ex.getErrorCode(),
            ex.getMessage(),
            Instant.now()
        );
        return ResponseEntity.status(code).body(problem);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiProblemView> onBeanValidation(MethodArgumentNotValidException ex) {
        String detail = ex.getBindingResult().getFieldErrors().stream()
            .findFirst()
            .map(err -> err.getField() + ": " + err.getDefaultMessage())
            .orElse("Invalid request payload");
        ApiProblemView problem = new ApiProblemView(
            "urn:resicomplex:iam:validation",
            "Bad Request",
            400,
            "VALIDATION_ERROR",
            detail,
            Instant.now()
        );
        return ResponseEntity.badRequest().body(problem);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiProblemView> onIllegalArg(IllegalArgumentException ex) {
        ApiProblemView problem = new ApiProblemView(
            "urn:resicomplex:iam:bad-argument",
            "Bad Request",
            400,
            "BAD_REQUEST",
            ex.getMessage(),
            Instant.now()
        );
        return ResponseEntity.badRequest().body(problem);
    }
}
