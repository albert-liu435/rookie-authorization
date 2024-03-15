package com.rookie.bigdata.security.userdetails;

import com.rookie.bigdata.domain.dto.CustomUserDetailsDto;
import com.rookie.bigdata.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @Classname CustomUserDetailsService
 * @Description
 * @Author rookie
 * @Date 2023/3/14 13:14
 * @Version 1.0
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final String USERNAME_NOT_FOUND_MESSAGE = "User with name (%s) not exists.";

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new CustomUserDetailsDto(
                Optional.ofNullable(userMapper.getUserRoleDto(username)).orElseThrow(() -> new UsernameNotFoundException(String.format(USERNAME_NOT_FOUND_MESSAGE, username)))
        );
    }


}
