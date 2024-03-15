package com.rookie.bigdata.mapper;

import com.rookie.bigdata.domain.Role;
import com.rookie.bigdata.domain.User;
import com.rookie.bigdata.domain.dto.UserRoleDto;
import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.mapping.FetchType;

import java.util.List;
import java.util.Set;

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


    @Select("SELECT * FROM USER where name = #{username}")
    @Results({
            @Result(property = "name", column = "name"),
            @Result(property = "password", column = "password"),
            @Result(property = "roles", column = "id", javaType = Set.class,
                    many = @Many(
                            select = "com.rookie.bigdata.mapper.RoleMapper.queryRoleName",
                            fetchType = FetchType.EAGER
                    )
            )
    })
    UserRoleDto getUserRoleDto(String username);

}
