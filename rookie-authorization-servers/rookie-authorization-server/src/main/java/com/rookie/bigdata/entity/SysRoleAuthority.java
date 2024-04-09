package com.rookie.bigdata.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
/**
 * @Author rookie
 * @Description 角色菜单多对多关联表
 * @Date 2024/4/9 23:27
 * @Version 1.0
 */
@Getter
@Setter
@TableName("sys_role_authority")
public class SysRoleAuthority implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 角色菜单关联表自增ID
     */
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    /**
     * 角色ID
     */
    private Integer roleId;

    /**
     * 权限菜单ID
     */
    private Integer authorityId;
}
