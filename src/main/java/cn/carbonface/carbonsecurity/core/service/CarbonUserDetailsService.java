package cn.carbonface.carbonsecurity.core.service;



import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.feignclient.UserClient;
import cn.carbonface.carboncommon.dto.userdto.User;
import cn.carbonface.carboncommon.dto.userdto.UserRole;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.HashSet;

import java.util.List;
import java.util.Set;

/**
 * @Classname CarbonFaceUserDetailsService
 * @Description for user auth service
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/18 10:18
 * @Version V1.0
 */
@Service
@Slf4j
public class CarbonUserDetailsService implements UserDetailsService {

    private final UserClient userClient;

    public CarbonUserDetailsService(UserClient userClient) {
        this.userClient = userClient;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userClient.getUserByUsername(username);
        if (user ==null){
            return null;
        }else{
            CarbonUserDetails carbonUserDetails = new CarbonUserDetails();
            BeanUtils.copyProperties(user, carbonUserDetails);
            Set<GrantedAuthority> authorities = new HashSet<>();
            List<UserRole> roleList = userClient.getRoleByUserId(carbonUserDetails.getId()); // user role list
            roleList.forEach(role -> {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRoleName()));
            });
            carbonUserDetails.setAuthorities(authorities);
            return carbonUserDetails;
        }
    }
}
