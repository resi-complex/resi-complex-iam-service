package com.resicomplex.iam.domain.port.out;

import com.resicomplex.iam.domain.model.UserAccount;
import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.model.UserStatus;
import java.util.List;
import java.util.Optional;

public interface UserRepositoryPort {
    UserAccount save(UserAccount user);
    Optional<UserAccount> findActiveById(String id);
    Optional<UserAccount> findActiveByEmail(String email);
    boolean existsByEmail(String email);
    List<UserAccount> findAllActive(UserRole roleFilter, UserStatus statusFilter);
}
