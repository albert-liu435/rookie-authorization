package com.rookie.bigdata.security.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @Classname CustomAuthenticationProvider
 * @Description
 * @Author rookie
 * @Date 2023/3/14 13:40
 * @Version 1.0
 */

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    public static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

    /**
     * 这里可以自定义加密器
     */
    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();

        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (bCryptPasswordEncoder.matches(password, userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
        }

        throw new BadCredentialsException("User's password is not correct.");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }


}
