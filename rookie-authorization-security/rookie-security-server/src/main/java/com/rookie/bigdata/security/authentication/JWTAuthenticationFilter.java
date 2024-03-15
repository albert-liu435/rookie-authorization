package com.rookie.bigdata.security.authentication;

import com.alibaba.fastjson2.JSON;
import com.rookie.bigdata.domain.RedisKey;
import com.rookie.bigdata.domain.User;
import com.rookie.bigdata.domain.dto.CustomUserDetailsDto;
import com.rookie.bigdata.security.SecurityConfig;
import com.rookie.bigdata.service.RedisService;
import com.rookie.bigdata.util.AccessTokenUtils;
import com.rookie.bigdata.util.ResponseUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * @Classname JWTAuthenticationFilter
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:01
 * @Version 1.0
 */

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    public static final Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    private static final String AUTHENTICATION_SUCCESS_MESSAGE = "Login success.";

    private static final String AUTHENTICATION_INCOMPLETE_MESSAGE = "User credential is null.";

    private static final String USERNAME_PARAMETER_NAME = "name";

    private static final String CSRF_TOKEN = SecurityConfig.CSRF_TOKEN;

    private static final String ACCESS_TOKEN = SecurityConfig.ACCESS_TOKEN;


    private final AuthenticationManager authenticationManager;


    private final RedisService redisService;

    private User user;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, RedisService redisService) {
        this.authenticationManager = authenticationManager;
        this.redisService = redisService;

        // 当 requestUrl 是 /auth/login 时会经过这个过滤器
        super.setFilterProcessesUrl(SecurityConfig.LOGIN_URI);
        super.setUsernameParameter(USERNAME_PARAMETER_NAME);
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 数据是通过 requestBody 传输
        this.user = JSON.parseObject(request.getInputStream(), StandardCharsets.UTF_8, User.class);

        if (Objects.isNull(user)) {
            ResponseUtils.forbiddenResponse(response, AUTHENTICATION_INCOMPLETE_MESSAGE);
            return null;
        }

        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getName(), user.getPassword())
            );
        } catch (AuthenticationException authenticationException) {
            unsuccessfulAuthentication(request, response, authenticationException);

            // 终止后续执行
            return null;
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        logger.debug("Successful authentication.");

        SecurityContextHolder.getContext().setAuthentication(authResult);
        final CustomUserDetailsDto customUserDetailsDto = (CustomUserDetailsDto) authResult.getPrincipal();

        // ~ 登陆成功后, 给响应头置入 access-token 和 csrf-token


        String accessToken = AccessTokenUtils.create(customUserDetailsDto);

        redisService.set(
                RedisKey.builder().prefix(customUserDetailsDto.getName()).suffix(ACCESS_TOKEN).build().of(),
                accessToken,
                AccessTokenUtils.LIFE_TIME
        );

        response.setHeader(
                ACCESS_TOKEN,
                // 缓存 access-token
                accessToken
        );

//        response.setHeader(
//                ACCESS_TOKEN,
//                // 缓存 access-token
//                redisService.set(
//                        RedisKey.builder().prefix(customUserDetailsDto.getName()).suffix(ACCESS_TOKEN).build().of(),
//                        AccessTokenUtils.create(customUserDetailsDto),
//                        AccessTokenUtils.LIFE_TIME
//                )
//        );

        response.setHeader(
                CSRF_TOKEN,
                (String) redisService.get(
                        RedisKey.builder().prefix(customUserDetailsDto.getName()).suffix(CSRF_TOKEN).build().of()
                )
        );

        ResponseUtils.okResponse(response, AUTHENTICATION_SUCCESS_MESSAGE);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        logger.debug("Unsuccessful authentication : delete cached csrf-token.");

        // 如果登陆失败, 清楚在 CsrfFilter 阶段已经缓存的无效的 csrf-token, 不会有 csrf-token 返回
        redisService.del(RedisKey.builder().prefix(user.getName()).suffix(SecurityConfig.CSRF_TOKEN).build().of());

        ResponseUtils.forbiddenResponse(response, failed.getMessage());
    }
}
