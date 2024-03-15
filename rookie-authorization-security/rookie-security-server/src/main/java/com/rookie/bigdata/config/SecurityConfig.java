//package com.rookie.bigdata.config;
//
//import com.rookie.bigdata.csrf.MyCsrfTokenRequestHandler;
//import com.rookie.bigdata.filter.CsrfHeaderFilter;
//import com.rookie.bigdata.filter.HttpServletRequestWrapFilter;
//import com.rookie.bigdata.filter.JWTAuthenticationFilter;
//import com.rookie.bigdata.filter.JWTAuthorizationFilter;
//import com.rookie.bigdata.provider.UserPasswordAuthenticationProvider;
//import org.apache.naming.HandlerRef;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Lazy;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
//import org.springframework.security.web.csrf.*;
//import org.springframework.security.web.firewall.DefaultHttpFirewall;
//import org.springframework.security.web.firewall.HttpFirewall;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//import static org.springframework.security.config.Customizer.withDefaults;
//
///**
// * @Class SecurityConfig
// * @Description
// * @Author rookie
// * @Date 2024/3/13 15:50
// * @Version 1.0
// */
//
//@Configuration
//@EnableWebSecurity(debug = true)
//public class SecurityConfig {
//
//    @Autowired
//    private AuthenticationFailureHandler customAuthenticationFailureHandler;
//
//    @Autowired
//    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;
//    @Lazy
//    @Autowired
//    private UserPasswordAuthenticationProvider userPasswordAuthenticationProvider;
//
//    @Autowired
//    private CsrfTokenRepository csrfTokenMemoryRepository;
//
//    @Autowired
//    private CsrfHeaderFilter csrfHeaderFilter;
//
//    /**
//     * @param http
//     * @return
//     * @throws Exception
//     */
//    @Bean
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//
//        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
//        // set the name of the attribute the CsrfToken will be populated on
//        requestHandler.setCsrfRequestAttributeName("_csrf");
//
////        MyCsrfTokenRequestHandler requestHandler = new MyCsrfTokenRequestHandler();
////        // set the name of the attribute the CsrfToken will be populated on
//////        requestHandler.setCsrfRequestAttributeName("_csrf");
//
//
//        http.csrf((csrf) -> {
//                    csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/login"))
//                            .csrfTokenRepository(csrfTokenMemoryRepository)
//                            .csrfTokenRequestHandler(requestHandler)
//                    ;
//                })
////                .addFilterAfter(new CsrfHeaderFilter(), JWTAuthorizationFilter.class)
//
//
//                .authorizeHttpRequests((authorize) -> authorize
//                                // 放行静态资源
//                                .requestMatchers("/auth/**").permitAll()
////                        .anyRequest().authenticated()
//                                .anyRequest().hasAnyAuthority("ROLE_ADMIN")
//                )
//
//                .formLogin((formLogin) -> formLogin.disable())
//                //请求包装类过滤器在CsrfFilter之前，为了解决参数多次获取的问题
//                .addFilterBefore(new HttpServletRequestWrapFilter(), CsrfFilter.class)
//                //
//                .addFilterAt(new JWTAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
//                .addFilterAfter(new JWTAuthorizationFilter(), JWTAuthenticationFilter.class)
//                .addFilterAfter(csrfHeaderFilter, CsrfFilter.class)
//                // 不需要 Session
//                .sessionManagement((sessionManagement) ->
//                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                );
//
//        return http.build();
//    }
//
//    @Bean
//    PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//
//    /**
//     * 身份管理器
//     *
//     * @return
//     */
//    @Bean
//    public AuthenticationManager authenticationManager() {
//
//        return new ProviderManager(userPasswordAuthenticationProvider);
//
//    }
//
//
//}
