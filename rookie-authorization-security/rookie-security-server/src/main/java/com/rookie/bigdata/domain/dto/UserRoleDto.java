package com.rookie.bigdata.domain.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * @Classname UUserRoleDto
 * @Description
 * @Author rookie
 * @Date 2023/3/14 11:44
 * @Version 1.0
 */
@Data
@NoArgsConstructor
public class UserRoleDto {

    // ~ USER Fields
    // -----------------------------------------------------------------------------------------------------------------
    private String name;
    private String password;

    // ~ ROLE_USER Fields
    private Set<String> roles;

}
