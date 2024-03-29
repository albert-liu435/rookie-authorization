package com.rookie.bigdata.authorization.token;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @Class CustomerOAuth2TokenCustomizer
 * @Description 自定义jwt，将权限信息放至jwt中
 * @Author rookie
 * @Date 2024/3/29 16:04
 * @Version 1.0
 */
public class CustomerOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {


    @Override
    public void customize(JwtEncodingContext context) {

        // 检查登录用户信息是不是UserDetails，排除掉没有用户参与的流程
        if (context.getPrincipal().getPrincipal() instanceof UserDetails user) {
            // 获取申请的scopes
            Set<String> scopes = context.getAuthorizedScopes();
            // 获取用户的权限
            Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
            // 提取权限并转为字符串
            Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptyList()).stream()
                    // 获取权限字符串
                    .map(GrantedAuthority::getAuthority)
                    // 去重
                    .collect(Collectors.toSet());

            // 合并scope与用户信息
            authoritySet.addAll(scopes);

            JwtClaimsSet.Builder claims = context.getClaims();
            // 将权限信息放入jwt的claims中（也可以生成一个以指定字符分割的字符串放入）
            claims.claim("authorities", authoritySet);
            // 放入其它自定内容
            // 角色、头像...
        }

    }


    //    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
//
//        return context -> {
//            // 检查登录用户信息是不是UserDetails，排除掉没有用户参与的流程
//            if (context.getPrincipal().getPrincipal() instanceof UserDetails user) {
//                // 获取申请的scopes
//                Set<String> scopes = context.getAuthorizedScopes();
//                // 获取用户的权限
//                Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
//                // 提取权限并转为字符串
//                Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptyList()).stream()
//                        // 获取权限字符串
//                        .map(GrantedAuthority::getAuthority)
//                        // 去重
//                        .collect(Collectors.toSet());
//
//                // 合并scope与用户信息
//                authoritySet.addAll(scopes);
//
//                JwtClaimsSet.Builder claims = context.getClaims();
//                // 将权限信息放入jwt的claims中（也可以生成一个以指定字符分割的字符串放入）
//                claims.claim("authorities", authoritySet);
//                // 放入其它自定内容
//                // 角色、头像...
//            }
//        };
//    }


}
