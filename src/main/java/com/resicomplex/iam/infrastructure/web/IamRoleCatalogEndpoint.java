package com.resicomplex.iam.infrastructure.web;

import com.resicomplex.iam.domain.model.UserRole;
import com.resicomplex.iam.domain.port.in.IamUseCasePort;
import com.resicomplex.iam.infrastructure.web.dto.IamPayloads.RoleCatalogItem;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IamRoleCatalogEndpoint {

    private final IamUseCasePort useCase;
    private final IamHeaderGuard guard;

    public IamRoleCatalogEndpoint(IamUseCasePort useCase, IamHeaderGuard guard) {
        this.useCase = useCase;
        this.guard = guard;
    }

    @GetMapping({"/roles", "/api/v1/auth/roles", "/api/v1/roles"})
    public List<RoleCatalogItem> fetchCatalog(HttpServletRequest req) {
        guard.requireAuthenticated(req);
        return useCase.listRolesCatalog().stream()
            .map(RoleCatalogItem::of)
            .toList();
    }
}
