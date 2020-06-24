package org.freshlegacycode.cloud.config.server;

import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.AUD;

import java.util.List;
import java.util.Arrays;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.AUD;

@EnableWebSecurity
public class OAuth2ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests(authorizeRequests ->
          authorizeRequests
          .anyRequest().authenticated()
          )
      .oauth2ResourceServer(oauth2ResourceServer ->
          oauth2ResourceServer
          .jwt(jwt ->
            {
              jwt.decoder(jwtDecoder());
            }
            )
          );
  }

  @Value("#{environment.REQUIRED_AUDIENCE}") String requiredAudience;

  OAuth2TokenValidator<Jwt> audienceValidator() {
    if (requiredAudience != null && requiredAudience != "") {
      return new JwtClaimValidator<List<String>>(AUD, aud -> aud.contains(requiredAudience));
    } else {
      return new JwtClaimValidator<List<String>>(AUD, aud -> false);
    }
  }

  @Value("#{environment.JWK_SET_URI}") String jwkSetUri;

  @Bean
  JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();

    OAuth2TokenValidator<Jwt> audienceValidator = audienceValidator();
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefault();
    OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

    jwtDecoder.setJwtValidator(withAudience);

    return jwtDecoder;
  }
}
