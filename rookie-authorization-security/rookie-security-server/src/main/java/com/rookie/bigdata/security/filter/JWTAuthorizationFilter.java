package com.rookie.bigdata.security.filter;

import com.rookie.bigdata.domain.RedisKey;
import com.rookie.bigdata.domain.dto.CustomUserDetailsDto;
import com.rookie.bigdata.security.SecurityConfig;
import com.rookie.bigdata.security.authentication.JWTAuthenticationFilter;
import com.rookie.bigdata.service.RedisService;
import com.rookie.bigdata.util.AccessTokenUtils;
import com.rookie.bigdata.util.RequestUtils;
import com.rookie.bigdata.util.ResponseUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @Classname JWTAuthorizationFilter
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:09
 * @Version 1.0
 */
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    public static final Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);


    private static final String UNAUTHORIZED_MESSAGE = "Unauthorized access.";

    /**
     * access-token 过期 或者 不是有效的 access-token
     */
    private static final String ACCESS_TOKEN_EXPIRED_MESSAGE = "Invalid access-token.";

    /**
     * 白名单, 放行 /auth/register 注册端点
     */
    private static final Set<String> WHITE_LIST = Stream.of(SecurityConfig.REGISTER_URI).collect(Collectors.toSet());

    private final RedisService redisService;

    public JWTAuthorizationFilter(RedisService redisService) {
        this.redisService = redisService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorization = request.getHeader(AccessTokenUtils.AUTHORIZATION_HEADER);

        // ~ without access-token
        // -------------------------------------------------------------------------------------------------------------
        if (WHITE_LIST.contains(RequestUtils.getQualifiedURI(request))) {
            filterChain.doFilter(request, response);
            return;
        }

        if (StringUtils.isBlank(authorization)) {
            ResponseUtils.unauthorizedResponse(response, UNAUTHORIZED_MESSAGE);
            return;
        }

        // ~ with access-token
        // -------------------------------------------------------------------------------------------------------------

        final String jwt = authorization.replaceFirst(AccessTokenUtils.BEARER_TOKEN_TYPE, StringUtils.EMPTY);
        final CustomUserDetailsDto customUserDetailsDto = AccessTokenUtils.getCustomUserDetails(jwt);

        // 如果 access-token 已经失效
        final RedisKey accessTokenKey = RedisKey.builder().prefix(customUserDetailsDto.getName()).suffix(SecurityConfig.ACCESS_TOKEN).build();
        if (Objects.isNull((String)redisService.get(accessTokenKey.of()))) {
            ResponseUtils.unauthorizedResponse(response, ACCESS_TOKEN_EXPIRED_MESSAGE);
            return;
        }

        // 每次授权的访问, 都延长 access-token 的过期时间, 返回新的 token
        redisService.expire(accessTokenKey.of(), AccessTokenUtils.LIFE_TIME);

        // 认证
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                customUserDetailsDto.getName(),
                customUserDetailsDto.getPassword(),
                customUserDetailsDto.getAuthorities()
        ));

        filterChain.doFilter(request, response);
    }
}

