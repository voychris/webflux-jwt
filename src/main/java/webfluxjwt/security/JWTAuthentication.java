package webfluxjwt.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JWTAuthentication extends AbstractAuthenticationToken {

    private String token;

    public JWTAuthentication(String token) {
        super(null);
        this.token = token;
    }

    public JWTAuthentication(String token, DecodedJWT decodedJWT, Collection<GrantedAuthority> authorities) {
        super(authorities);
        super.setDetails(decodedJWT.getSubject());

        this.token = token;

        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return super.getDetails();
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    public String getToken() {
        return token;
    }
}
