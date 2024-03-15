package com.rookie.bigdata.security.csrf;

import com.alibaba.fastjson2.JSON;
import com.rookie.bigdata.domain.RedisKey;
import com.rookie.bigdata.domain.User;
import com.rookie.bigdata.security.SecurityConfig;
import com.rookie.bigdata.security.exception.UserInfoIncompleteException;
import com.rookie.bigdata.service.RedisService;
import com.rookie.bigdata.util.AccessTokenUtils;
import com.rookie.bigdata.util.CsrfTokenUtils;
import com.rookie.bigdata.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;


import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @Classname CsrfTokenRedisRepository
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:14
 * @Version 1.0
 */
@Component
public class CsrfTokenRedisRepository implements CsrfTokenRepository {

    public static final Logger logger = LoggerFactory.getLogger(CsrfTokenRedisRepository.class);

    private static final String CSRF_PARAMETER_NAME = "_csrf";


    private static final String CSRF_HEADER_NAME = "X-CSRF-TOKEN";

    private static final String CSRF_TOKEN = SecurityConfig.CSRF_TOKEN;
    /**
     * 白名单, 放行 /auth/register 注册端点
     */
    private static final Set<String> IGNORING_SAVING_TOKEN_LIST = Stream.of(SecurityConfig.REGISTER_URI).collect(Collectors.toSet());

    @Autowired
    private RedisService redisService;


    private String name;


    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, CsrfTokenUtils.create());
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        logger.debug("csrf filter: redis csrf token repository: save token");

        if (Objects.isNull(token)) {
            redisService.del(RedisKey.builder().prefix(name).suffix(CSRF_TOKEN).build().of());
            return;
        }

        // 缓存 csrf-token
        final String csrfToken = token.getToken();
        redisService.set(RedisKey.builder().prefix(name).suffix(CSRF_TOKEN).build().of(), csrfToken);

        if (org.apache.commons.lang3.StringUtils.equals(RequestUtils.getQualifiedURI(request), SecurityConfig.LOGIN_URI)) {
            // 登录端点的请求在登录成功后设置 JWTAuthenticationFilter#successfulAuthentication
            return;
        }

        // 将 csrf-token 放入响应头
        response.setHeader(CSRF_TOKEN, csrfToken);
    }

    @SneakyThrows
    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        logger.debug("csrf filter: redis csrf token repository: load token");

        final User user = JSON.parseObject(request.getInputStream(), StandardCharsets.UTF_8, User.class);
        if (Objects.nonNull(user)) {
            this.name = user.getName();
        } else {
            try {
                this.name = AccessTokenUtils.getSubject(
                        request.getHeader(AccessTokenUtils.AUTHORIZATION_HEADER).replaceFirst(AccessTokenUtils.BEARER_TOKEN_TYPE, "")
                );
            } catch (Exception ignored) {
                throw new UserInfoIncompleteException("Cannot retrieve user's name from request (neither inputStream nor header Authorization)");
            }
        }


        if (StringUtils.isEmpty(this.name)) {
            throw new UserInfoIncompleteException("Cannot retrieve user's name from request (neither inputStream nor header Authorization)");
        }

        // ~ 避免触发 saveToken
        // 1. 如果是注册端点, 生成一个临时的 csrf-token.
        final String qualifiedURI = RequestUtils.getQualifiedURI(request);
        if (IGNORING_SAVING_TOKEN_LIST.contains(qualifiedURI)) {
            return generateToken(request);
        }
//        // 2. 如果 (非登录端点) 请求头中没有 X-CSRF-TOKEN, 生成一个临时的 csrf-token.
//        if (StringUtils.isBlank(request.getHeader(CSRF_HEADER_NAME)) && !StringUtils.equals(qualifiedURI, SecurityConfiguration.LOGIN_URI)) {
//            return generateToken(request);
//        }

        // 返回正常的 Token
        final String csrfToken = getCachedToken();
        return StringUtils.isEmpty(csrfToken) ? null : new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, csrfToken);
    }


    private String getCachedToken() {
        final String csrfToken = (String) redisService.get(RedisKey.builder().prefix(name).suffix(CSRF_TOKEN).build().of());

        if (StringUtils.isEmpty(csrfToken)) {
            return "";

        }
        return csrfToken;

    }

}
