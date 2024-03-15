package com.rookie.bigdata.domain;

import lombok.Data;

import java.io.Serializable;

/**
 * @Classname Role
 * @Description 角色
 * @Author rookie
 * @Date 2023/3/10 10:04
 * @Version 1.0
 */
@Data
public class Role implements Serializable {

    private String id;
    private String name;
}
