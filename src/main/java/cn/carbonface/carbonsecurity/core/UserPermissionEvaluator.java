package cn.carbonface.carbonsecurity.core;

import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.feignclient.UserClient;
import cn.carbonface.carboncommon.dto.userdto.RoleAuth;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @Classname UserPermissionEvaluator
 * @Description TODO
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/31 14:13
 * @Version V1.0
 */
@Component
public class UserPermissionEvaluator implements PermissionEvaluator {

    private final UserClient userClient;

    public UserPermissionEvaluator(UserClient userClient) {
        this.userClient = userClient;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetUrl, Object permission) {
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) authentication.getPrincipal();
        Set<String> permissions = new HashSet<>(); // 用户权限
        List<RoleAuth> authList = userClient.getAuthByUserId(carbonUserDetails.getId());
        authList.forEach(auth -> {
            permissions.add(auth.getAuthPermission());
        });

        // 判断是否拥有权限
        if (permissions.contains(permission.toString())) {
            return true;
        }
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable serializable, String s, Object o) {
        return false;
    }
}
