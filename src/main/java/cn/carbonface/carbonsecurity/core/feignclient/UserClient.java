package cn.carbonface.carbonsecurity.core.feignclient;


import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.userdto.RoleAuth;
import cn.carbonface.carboncommon.dto.userdto.User;
import cn.carbonface.carboncommon.dto.userdto.UserRole;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * @Classname UserClient
 * @Description carbon-user service feign client
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/31 17:31
 * @Version V1.0
 */

@FeignClient("carbon-user")
public interface UserClient {

    @PostMapping("user/getRoleByUserId")
    ApiResult<List<UserRole>> getRoleByUserId(@RequestParam("userId") Long userId);

    @PostMapping("user/getAuthByUserId")
    ApiResult<List<RoleAuth>> getAuthByUserId(@RequestParam("userId")Long userId);

    @PostMapping("user/getUserByUsername")
    ApiResult<User> getUserByUsername(@RequestParam("username")String username);
}
