package com.rookie.bigdata.config;

import com.rookie.bigdata.provider.UserPasswordAuthenticationProvider;
import org.apache.naming.HandlerRef;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
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
//@EnableWebSecurity
@EnableWebSecurity(debug = true)
public class SecurityConfig {


    //@Lazy为了解决循环依赖的问题
    @Lazy
    @Autowired
    private UserPasswordAuthenticationProvider userPasswordAuthenticationProvider;

//    private UserPasswordAuthenticationProvider userPasswordAuthenticationProvider;


//    @Autowired
//    void setUserPasswordAuthenticationProvider(UserPasswordAuthenticationProvider userPasswordAuthenticationProvider) {
//        this.userPasswordAuthenticationProvider = userPasswordAuthenticationProvider;
//    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }








    /**
     * 过滤器链，可以查看DebugFilter
     *
     * Security filter chain: [
     *   DisableEncodeUrlFilter
     *   WebAsyncManagerIntegrationFilter
     *   SecurityContextHolderFilter
     *   HeaderWriterFilter
     *   CsrfFilter
     *   LogoutFilter
     *   UsernamePasswordAuthenticationFilter
     *   DefaultLoginPageGeneratingFilter
     *   DefaultLogoutPageGeneratingFilter
     *   BasicAuthenticationFilter
     *   RequestCacheAwareFilter
     *   SecurityContextHolderAwareRequestFilter
     *   AnonymousAuthenticationFilter
     *   ExceptionTranslationFilter
     *   AuthorizationFilter
     * ]
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {


//        http.authorizeRequests().anyRequest().authenticated();

        http
                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .anyRequest().authenticated()
                );

//        http.authorizeHttpRequests(new Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>() {
//            @Override
//            public void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorizationManagerRequestMatcherRegistry) {
//                authorizationManagerRequestMatcherRegistry.anyRequest().authenticated();
//            }
//        });


//        http.authenticationManager(new ProviderManager(myAuthenticationProvider));
        // http.authenticationManager()
//        http.authenticationProvider(userPasswordAuthenticationProvider)
//                .formLogin()
//                .and()
//                .httpBasic();

        http.authenticationProvider(userPasswordAuthenticationProvider)
                .formLogin(withDefaults())
//                .and()
                .httpBasic(withDefaults());

        return http.build();
    }

//    @Bean
//    PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }


    @Bean
    HttpFirewall httpFirewall() {
        return new DefaultHttpFirewall();
    }


}
