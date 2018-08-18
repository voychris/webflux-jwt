package webfluxjwt.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import java.io.UnsupportedEncodingException;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

    @Value("${security.secret:secret}")
    private String secret;

    @Value("${security.apiId:secured-api}")
    private String apiId;

    @Value("${security.securedPath:/api/**}")
    private String securedPath;

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws UnsupportedEncodingException {
        AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
            JWTReactiveAuthenticationManager.getInstance(secret, apiId));
        authenticationFilter.setAuthenticationConverter(new JWTAuthenticationConverter());

        return http
            .csrf().disable()
            .logout().disable()
            .securityMatcher(ServerWebExchangeMatchers.pathMatchers(securedPath))
            .addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .authorizeExchange()
            .anyExchange().access(new JWTClaimsReactiveAuthorizationManager("api:read"))
            .and().build();
    }
}
