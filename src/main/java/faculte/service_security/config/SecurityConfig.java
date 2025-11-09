package faculte.service_security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import faculte.service_security.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private PasswordEncoder passwordEncoder ;
    private RsaKeys rsaKeys;
    private CustomUserDetailsService customUserDetailsService;


    public SecurityConfig(PasswordEncoder passwordEncoder, RsaKeys rsaKeys,CustomUserDetailsService customUserDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.rsaKeys = rsaKeys;
        this.customUserDetailsService = customUserDetailsService;
    }

    //gestion authentification avec springsecurity
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(customUserDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(daoAuthenticationProvider);
    }
//    @Bean
//    public UserDetailsManager userDetailsManager() {
//
//        return new InMemoryUserDetailsManager(
//               // User.withUsername("user").password("{noop}passwordUser").roles("USER").build(),  noop dit qu spring que le password clair
//                User.withUsername("user1").password(passwordEncoder.encode("passwordUser1")).roles("USER").build(),
//                User.withUsername("user3").password(passwordEncoder.encode("passwordAdmin")).roles("ADMIN").build()
//
//                );
//    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS) )
                .csrf(csrf -> csrf.disable())
                .authorizeRequests(auth -> auth.requestMatchers("/v1/users/login").permitAll())
                .authorizeRequests(auth -> auth.requestMatchers("/v1/users/refresh").permitAll())
                .authorizeRequests(auth -> auth.anyRequest().authenticated())
                //OAuth2
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)

                .httpBasic(Customizer.withDefaults())
                .build();
    }
    //encoder le token
    @Bean
    JwtEncoder  jwtEncoder(RsaKeys rsaKeys) {
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey())
                .privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    //decoder le token
    @Bean
    JwtDecoder jwtDecoder(RsaKeys rsaKeys) {

        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }
}
