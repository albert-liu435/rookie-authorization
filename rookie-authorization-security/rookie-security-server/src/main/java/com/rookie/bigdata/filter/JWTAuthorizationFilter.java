//package com.rookie.bigdata.filter;
//
//import com.rookie.bigdata.domain.CustomUserDetails;
//import com.rookie.bigdata.util.JWTUtils;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//
//import java.io.IOException;
//import java.util.Set;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
///**
// * @Classname JWTAuthorizationFilter
// * @Description
// * @Author rookie
// * @Date 2023/3/10 11:29
// * @Version 1.0
// */
//@Slf4j
//public class JWTAuthorizationFilter extends OncePerRequestFilter {
//
//    private static final Set<String> WHITE_LIST = Stream.of("/auth/register").collect(Collectors.toSet());
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        log.debug("authorization filter doFilterInternal");
//        final String authorization = request.getHeader(JWTUtils.TOKEN_HEADER);
//        log.debug("raw-access-token: {}", authorization);
//
//        // Branch A: 如果请求头中没有 Authorization
//        if (StringUtils.isEmpty(authorization)) {
//            // 白名单放行
//            if (WHITE_LIST.contains(request.getRequestURI())) {
//                chain.doFilter(request, response);
//            } else {
//                response.getWriter().write("not permited!");
//            }
//            return;
//        }
//
//        // Branch B: 如果请求头中有 Bear xxx, 设置认证信息
//        final String jsonWebToken = authorization.replace(JWTUtils.TOKEN_PREFIX, "");
//
//        //  用 Redis 的过期控制 token, 而不用 jwt 的 Expiration
//        // if (JWTUtils.hasExpired(jsonWebToken)) {
//        //     response.getWriter().write("access-token 已过期, 请重新登陆!");
//        // }
//        //  每一次携带正确 token 的访问, 都刷新 Redis 的过期时间
//
//        CustomUserDetails customUserDetails = JWTUtils.userDetails(jsonWebToken);
//        SecurityContextHolder.getContext().setAuthentication(
//                new UsernamePasswordAuthenticationToken(
//                        customUserDetails.getName(),
//                        //  Json Web Token 中不能携带用户密码
//                        customUserDetails.getPassword(),
//                        customUserDetails.getAuthorities()
//                )
//        );
//        chain.doFilter(request, response);
//    }
//}
