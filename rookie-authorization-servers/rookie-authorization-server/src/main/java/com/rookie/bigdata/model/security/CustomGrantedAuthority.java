package com.rookie.bigdata.model.security;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;


/**
 * @Class CustomGrantedAuthority
 * @Description 自定义权限类
 * @Author rookie
 * @Date 2024/4/10 9:16
 * @Version 1.0
 */
@Data
@JsonSerialize
@NoArgsConstructor
@AllArgsConstructor
public class CustomGrantedAuthority implements GrantedAuthority {

    private String authority;

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
