package com.rookie.bigdata.service.impl;


import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.rookie.bigdata.entity.SysRoleAuthority;
import com.rookie.bigdata.mapper.SysRoleAuthorityMapper;
import com.rookie.bigdata.service.ISysRoleAuthorityService;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 角色菜单多对多关联表 服务实现类
 * </p>
 *
 * @author vains
 * @since 2023-07-04
 */
@Service
public class SysRoleAuthorityServiceImpl extends ServiceImpl<SysRoleAuthorityMapper, SysRoleAuthority> implements ISysRoleAuthorityService {

}
