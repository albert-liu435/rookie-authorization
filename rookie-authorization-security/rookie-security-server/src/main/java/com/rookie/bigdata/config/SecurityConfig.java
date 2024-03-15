package com.rookie.bigdata.config;

import com.rookie.bigdata.filter.JWTAuthenticationFilter;
import com.rookie.bigdata.filter.JWTAuthorizationFilter;
import com.rookie.bigdata.provider.UserPasswordAuthenticationProvider;
import org.apache.naming.HandlerRef;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @Class SecurityConfig
 * @Description
 * @Author rookie
 * @Date 2024/3/13 15:50
 * @Version 1.0
 */

@Configuration
public class SecurityConfig {

    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    @Lazy
    @Autowired
    private UserPasswordAuthenticationProvider userPasswordAuthenticationProvider;


    /**
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.csrf((csrf) -> csrf.disable())
//        http.csrf().disable()
                .authorizeRequests()
                .requestMatchers("/auth/**").permitAll()
//                .antMatchers("/auth/**").permitAll()

                .anyRequest().hasAnyAuthority("ROLE_ADMIN")
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                // 让校验 Token 的过滤器在身份认证过滤器之后
                .addFilterAfter(new JWTAuthorizationFilter(), JWTAuthenticationFilter.class)
                // 不需要 Session
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * 身份管理器
     *
     * @return
     */
    @Bean
    public AuthenticationManager authenticationManager() {

        return new ProviderManager(userPasswordAuthenticationProvider);

    }


}
