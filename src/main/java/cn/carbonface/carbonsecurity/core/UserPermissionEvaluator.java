package cn.carbonface.carbonsecurity.core;

import cn.carbonface.carboncommon.dto.ApiResult;
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
 * Classname: UserPermissionEvaluator
 * Description: user permissions control for annotation @PreAuthorize
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/3/31 14:13
 * @version V1.0
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
        Set<String> permissions = new HashSet<>(); // user authorization
        ApiResult<List<RoleAuth>> authResult = userClient.getAuthByUserId(carbonUserDetails.getId());
        authResult.getData();
        if (authResult.success()) {
            List<RoleAuth> data = authResult.getData();
            data.forEach(auth -> {
                permissions.add(auth.getAuthPermission());
            });
        }
        // if has permission return true
        return permissions.contains(permission.toString());
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable serializable, String s, Object o) {
        return false;
    }
}
