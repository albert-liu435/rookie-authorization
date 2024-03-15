package com.rookie.bigdata.security;


import com.rookie.bigdata.security.access.CustomAccessDeniedHandler;
import com.rookie.bigdata.security.authentication.JWTAuthenticationFilter;
import com.rookie.bigdata.security.config.FilterSecurityInterceptorPostProcessor;
import com.rookie.bigdata.security.filter.HttpServletRequestWrapFilter;
import com.rookie.bigdata.security.filter.JWTAuthorizationFilter;
import com.rookie.bigdata.security.web.CustomAuthenticationEntryPoint;
import com.rookie.bigdata.service.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

/**
 * @Classname SecurityConfig
 * @Description
 * @Author rookie
 * @Date 2023/3/14 12:08
 * @Version 1.0
 */
@Configuration
public class SecurityConfig {


    public static final String ACCESS_TOKEN = "access-token";

    public static final String CSRF_TOKEN = "csrf-token";

    public static final String LOGIN_URI = "/auth/login";

    public static final String REGISTER_URI = "/auth/register";


    @Autowired
    private AuthenticationProvider customAuthenticationProvider;

    @Autowired
    private CsrfTokenRepository csrfTokenRedisRepository;

    @Autowired
    private AccessDecisionManager accessDecisionManager;


    @Autowired
    private FilterInvocationSecurityMetadataSource securityMetadataSource;


    @Autowired
    private RedisService redisService;

    /**
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.csrf((csrf) -> {
            csrf.ignoringRequestMatchers(LOGIN_URI, REGISTER_URI)
                    .csrfTokenRepository(csrfTokenRedisRepository)
//                    .csrfTokenRequestHandler(requestHandler)
            ;
        })
//        http
//                .csrf().ignoringAntMatchers(LOGIN_URI, REGISTER_URI).csrfTokenRepository(csrfTokenRedisRepository)



//                .and()
                .addFilterBefore(new HttpServletRequestWrapFilter(), CsrfFilter.class)

                .authorizeRequests((authorizeRequests) ->
                        authorizeRequests
                                .requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated()
                                .withObjectPostProcessor(new FilterSecurityInterceptorPostProcessor(accessDecisionManager, securityMetadataSource))
                )
                // ~ 基础权限设定
                // -----------------------------------------------------------------------------------------------------
//                .antMatchers("/auth/**").permitAll()

                // ~ 动态权限设定
                // -----------------------------------------------------------------------------------------------------
//                .anyRequest().authenticated()


//                .withObjectPostProcessor(new FilterSecurityInterceptorPostProcessor(accessDecisionManager, securityMetadataSource))
                // ~ 禁用 Session: Spring Security will never create an HttpSession and it will never use it to obtain the SecurityContext
                // -----------------------------------------------------------------------------------------------------
//                .and()

                // 不需要 Session
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // ~ 添加 JWTAuthenticationFilter 和 JWTAuthorizationFilter
                // -----------------------------------------------------------------------------------------------------
//                .and()
                .addFilterAt(new JWTAuthenticationFilter(authenticationManager(), redisService), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new JWTAuthorizationFilter(redisService), JWTAuthenticationFilter.class)

                // ~ 异常处理: 处理 AccessDeniedException 和 AuthenticationException
                // -----------------------------------------------------------------------------------------------------
                .exceptionHandling()
                .accessDeniedHandler(new CustomAccessDeniedHandler())
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint());


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

        return new ProviderManager(customAuthenticationProvider);

    }

    @Bean
    public AntPathMatcher antPathMatcher() {
        return new AntPathMatcher();
    }


}
