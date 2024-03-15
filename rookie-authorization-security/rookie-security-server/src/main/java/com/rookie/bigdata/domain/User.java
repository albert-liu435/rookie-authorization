package com.rookie.bigdata.domain;

import lombok.Data;

import java.io.Serializable;

/**
 * @Classname User
 * @Description 用户
 * @Author rookie
 * @Date 2023/3/10 10:03
 * @Version 1.0
 */
@Data
public class User implements Serializable {
    private int id;
    private String name;
    private String password;

//    private String role;
}
