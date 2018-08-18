package webfluxjwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class JWTReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private JWTVerifier jwtVerifier;

    public static JWTReactiveAuthenticationManager getInstance(String secret, String apiId) throws UnsupportedEncodingException {
        Algorithm hmac256 = Algorithm.HMAC256(secret);
        JWTVerifier jwtVerifier = JWT.require(hmac256).withAudience(apiId).build();
        return new JWTReactiveAuthenticationManager(jwtVerifier);
    }

    private JWTReactiveAuthenticationManager(JWTVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        JWTAuthentication jwtAuthentication = (JWTAuthentication) authentication;

        String token = jwtAuthentication.getToken();

        if (token == null || token.trim().isEmpty()) {
            return Mono.error(new InsufficientAuthenticationException("Missing JWT"));
        }

        DecodedJWT decodedJWT;

        try {
            decodedJWT = jwtVerifier.verify(jwtAuthentication.getToken());
        } catch (Exception e) {
            return Mono.error(new InsufficientAuthenticationException("Invalid JWT Token", e));
        }

        return doAuthenticate(token, decodedJWT);
    }

    private Mono<Authentication> doAuthenticate(String token, DecodedJWT decodedJWT) {
        Claim claim = decodedJWT.getClaim("perms");

        List<String> permissions = !claim.isNull() ? claim.asList(String.class) : new ArrayList<>();

        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String p : permissions) {
            authorities.add(new SimpleGrantedAuthority(p.toLowerCase()));
        }

        return Mono.just(new JWTAuthentication(token, decodedJWT, authorities));
    }
}
