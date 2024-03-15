//package com.rookie.bigdata.service;
//
//import com.rookie.bigdata.domain.CustomUserDetails;
//import com.rookie.bigdata.domain.Role;
//import com.rookie.bigdata.domain.User;
//import com.rookie.bigdata.mapper.UserMapper;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import java.util.ArrayList;
//import java.util.List;
//
///**
// * @Classname UserDetailsServiceImpl
// * @Description 查询用户信息
// * @Author rookie
// * @Date 2023/3/10 10:01
// * @Version 1.0
// */
//@Service
//public class UserDetailsServiceImpl implements UserDetailsService {
//
//
//    @Autowired
//    private UserMapper userMapper;
//
//
//    /**
//     * 根据用户名查询用户信息，并封装为 UserDetailsUserDetails
//     *
//     * @param username
//     * @return
//     * @throws UsernameNotFoundException
//     */
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        // 根据用户名查询数据库，查到对应的用户
//        User myUser = userMapper.loadUserByUsername(username);
//
//        // 做一些异常处理，没有找到用户之类的
//        if (myUser == null) {
//            throw new UsernameNotFoundException("用户不存在");
//        }
//
//        // 根据用户ID，查询用户的角色
//        List<Role> roles = userMapper.findRoleByUserId(myUser.getId());
//        // 添加角色
//        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
//        for (Role role : roles) {
//            authorities.add(new SimpleGrantedAuthority(role.getName()));
//        }
//        // 构建 Security 的 User 对象
//        return new CustomUserDetails(myUser, authorities);
//    }
//}
