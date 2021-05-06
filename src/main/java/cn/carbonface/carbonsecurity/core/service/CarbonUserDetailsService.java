package cn.carbonface.carbonsecurity.core.service;



import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.exception.CarbonException;
import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.feignclient.UserClient;
import cn.carbonface.carboncommon.dto.userdto.User;
import cn.carbonface.carboncommon.dto.userdto.UserRole;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.HashSet;

import java.util.List;
import java.util.Set;

/**
 * Classname: CarbonFaceUserDetailsService
 * Description: for user auth service
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/3/18 10:18
 * @version V1.0
 */
@Service
@Slf4j
public class CarbonUserDetailsService implements UserDetailsService {

    private final UserClient userClient;

    public CarbonUserDetailsService(UserClient userClient) {
        this.userClient = userClient;
    }

    @Override
    public UserDetails loadUserByUsername(String username){
        User user = null;
        ApiResult<User> userResult = userClient.getUserByUsername(username);
        if (userResult.success()){
            user = userResult.getData();
        }
        if (user ==null){
            return null;//there might be a bug when feign client invoke returns a user object but contains nothing
        }else{
            CarbonUserDetails carbonUserDetails = new CarbonUserDetails();
            BeanUtils.copyProperties(user, carbonUserDetails);
            Set<GrantedAuthority> authorities = new HashSet<>();
            ApiResult<List<UserRole>> apiResult = userClient.getRoleByUserId(carbonUserDetails.getId()); // user role list
            if (apiResult.success()) {
                List<UserRole> roleList = apiResult.getData();
                roleList.forEach(role -> {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRoleName()));
                });
            }
            carbonUserDetails.setAuthorities(authorities);
            return carbonUserDetails;
        }
    }
}
