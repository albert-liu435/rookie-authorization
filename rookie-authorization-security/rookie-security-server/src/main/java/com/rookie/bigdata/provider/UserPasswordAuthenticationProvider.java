package com.rookie.bigdata.provider;

import com.rookie.bigdata.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @Classname UserPasswordAuthenticationProvider
 * @Description 进行账号密码验证
 * @Author rookie
 * @Date 2023/3/10 10:18
 * @Version 1.0
 */
@Service
public class UserPasswordAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取用户输入的用户名和密码
        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();
        // 获取封装用户信息的对象
        UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);
        // 进行密码的比对
        boolean flag = bCryptPasswordEncoder.matches(password, userDetails.getPassword());
        // 校验通过
        if (flag) {
            // 将权限信息也封装进去
            return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
        }

        throw new AuthenticationException("用户密码错误") {
        };
    }

//    @Override
//    public boolean supports(Class<?> aClass) {
//        return true;
//    }

    @Override
    public boolean supports(Class<?> authentication) {

        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
