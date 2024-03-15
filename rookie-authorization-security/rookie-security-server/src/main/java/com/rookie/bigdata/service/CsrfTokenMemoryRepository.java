//package com.rookie.bigdata.service;
//
//import com.alibaba.fastjson2.JSON;
//import com.alibaba.fastjson2.JSONException;
//import com.fasterxml.jackson.core.io.JsonEOFException;
//import com.rookie.bigdata.domain.CustomUserDetails;
//import com.rookie.bigdata.domain.User;
//import com.rookie.bigdata.util.JWTUtils;
//import com.rookie.bigdata.util.MyMap;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.SneakyThrows;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
//import org.springframework.security.web.csrf.CsrfToken;
//import org.springframework.security.web.csrf.CsrfTokenRepository;
//import org.springframework.security.web.csrf.DefaultCsrfToken;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//
//
//import java.nio.charset.StandardCharsets;
//import java.util.Objects;
//import java.util.Optional;
//import java.util.UUID;
//
///**
// * @Classname CsrfTokenMemoryRepository
// * @Description
// * @Author rookie
// * @Date 2023/3/10 14:29
// * @Version 1.0
// */
//@Slf4j
//@Component
//public class CsrfTokenMemoryRepository implements CsrfTokenRepository {
//
//    /**
//     * parameterName
//     */
//    private static final String CSRF_PARAMETER_NAME = "_csrf";
//
//    /**
//     * headerName
//     */
//    private static final String CSRF_HEADER_NAME = "X-CSRF-TOKEN";
//
//    private User user;
//
//    private String name;
//
//    //存储csrf token，这里在生产环境可以更改为数据库或者redis
//    private MyMap map = MyMap.getMyMap();
//
//    /**
//     * 生成csrf token
//     *
//     * @param request
//     * @return
//     */
//    @Override
//    public CsrfToken generateToken(HttpServletRequest request) {
//        final String csrfToken = StringUtils.replace(UUID.randomUUID().toString(), "-", "");
//        log.debug("csrf filter: redis csrf token repository: generate token: {}", csrfToken);
//
//        return new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, csrfToken);
//    }
//
//    /**
//     * 该方法会被调用次数: <br>
//     * 1. 第一次是在 CsrfFilter 中, 当 loadToken 的调用返回 null 时;<br>
//     * 2. (非匿名用户) 第二次是在 {@link CsrfAuthenticationStrategy#onAuthentication(Authentication, HttpServletRequest, HttpServletResponse)} 用于执行清除, 此时传入的参数 token 为 null;
//     * 3. (非匿名用户) 第三次实在 {@link CsrfAuthenticationStrategy#onAuthentication(Authentication, HttpServletRequest, HttpServletResponse)} 用于更新;
//     */
//    @SneakyThrows
//    @Override
//    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
//
//        log.debug("csrf filter: redis csrf token repository: save token");
//
//        //
//        if (Objects.isNull(token)) {
//            log.debug("csrf filter: do nothing while token is null. The token's lifecycle will be handled by Redis.");
//            return;
//        }
//
////        if(null ==user){
////            throw new AuthenticationException("LoginUser info is null!");
////        }
//
////        String name = Optional.ofNullable(user).orElseThrow(() -> new AuthenticationException("LoginUser info is null!") {
////        }).getName();
//
//        map.put(name, token.getToken());
//
//        response.setHeader("csrf-token", token.getToken());
//
//    }
//
//    @SneakyThrows
//    @Override
//    public CsrfToken loadToken(HttpServletRequest request) {
//
//
//        try {
//           this.user = JSON.parseObject(request.getInputStream(), StandardCharsets.UTF_8, User.class);
//        }catch (JSONException e){
//            this.user=null;
//        }
//
//
//
//        if (null == user) {
//            log.debug("authorization filter doFilterInternal");
//            final String authorization = request.getHeader(JWTUtils.TOKEN_HEADER);
//            log.debug("raw-access-token: {}", authorization);
//
//
//            // Branch B: 如果请求头中有 Bear xxx, 设置认证信息
//            final String jsonWebToken = authorization.replace(JWTUtils.TOKEN_PREFIX, "");
//
//            //  用 Redis 的过期控制 token, 而不用 jwt 的 Expiration
//            // if (JWTUtils.hasExpired(jsonWebToken)) {
//            //     response.getWriter().write("access-token 已过期, 请重新登陆!");
//            // }
//            //  每一次携带正确 token 的访问, 都刷新 Redis 的过期时间
//
//            CustomUserDetails customUserDetails = JWTUtils.userDetails(jsonWebToken);
//            //TODO user为空时的处理,第一次的时候为空，所以会进行生成，后面如果不为空的话就不会再次生成了
//            String username = customUserDetails.getUsername();
//            this.name = username;
//        } else {
//            this.name = user.getName();
//
//            //user不为空，说明是登录，则进行
//            return null;
//
//        }
//        try {
//            final String csrfToken = map.get(this.name);
//
//            return StringUtils.isEmpty(csrfToken) ? null : new DefaultCsrfToken(
//                    CSRF_HEADER_NAME,
//                    CSRF_PARAMETER_NAME,
//                    csrfToken
//            );
//        } catch (RuntimeException ignored) {
//            return null;
//        }
//    }
//}
