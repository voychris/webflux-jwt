package webfluxjwt.security;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

class JwtClaimsReactiveAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private String requiredAuthority;

    JwtClaimsReactiveAuthorizationManager(String requiredAuthority) {
        this.requiredAuthority = requiredAuthority;
    }

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext object) {
        return authentication
            .map(auth ->
                auth.getAuthorities().stream().anyMatch(it ->
                    it.getAuthority().equals(requiredAuthority)))
            .map(AuthorizationDecision::new);
    }
}
