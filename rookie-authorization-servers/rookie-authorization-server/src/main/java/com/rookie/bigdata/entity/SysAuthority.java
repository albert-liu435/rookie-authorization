package com.rookie.bigdata.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
/**
 * @Author rookie
 * @Description 系统菜单表
 * @Date 2024/4/9 23:26
 * @Version 1.0
 */
@Getter
@Setter
@TableName("sys_authority")
public class SysAuthority implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 菜单自增ID
     */
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    /**
     * 菜单名称
     */
    private String name;

    /**
     * 父菜单ID
     */
    private Integer menuPid;

    /**
     * 跳转URL
     */
    private String url;

    /**
     * 所需权限
     */
    private String authority;

    /**
     * 排序
     */
    private Byte sort;

    /**
     * 0:菜单,1:接口
     */
    private Byte type;

    /**
     * 0:启用,1:删除
     */
    private Boolean deleted;

    /**
     * 创建时间
     */
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    /**
     * 创建人
     */
    private Integer createUserId;
}
