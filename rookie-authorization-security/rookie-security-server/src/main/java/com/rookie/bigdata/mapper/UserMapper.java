package com.rookie.bigdata.mapper;

import com.rookie.bigdata.domain.Role;
import com.rookie.bigdata.domain.User;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * @Classname UserMapper
 * @Description
 * @Author rookie
 * @Date 2023/3/10 10:02
 * @Version 1.0
 */
public interface UserMapper {

    @Select("SELECT * FROM USER WHERE name = #{name}")
    User loadUserByUsername(String name);

    @Select("SELECT role.name FROM ROLE as role WHERE role.id in (SELECT role_id FROM ROLE_USER as r_s JOIN USER as u ON r_s.user_id = u.id and u.id = #{id})")
    List<Role> findRoleByUserId(int id);

}
