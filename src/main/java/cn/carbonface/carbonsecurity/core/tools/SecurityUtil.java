package cn.carbonface.carbonsecurity.core.tools;

import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Classname: SecurityUtil
 * Description: util for service to get current login user
 *
 * @author carbonface <553127022@qq.com>
 * Date: 2021/6/3 17:16
 * @version v1.0
 */
public class SecurityUtil {

    public static CarbonUserDetails getCurrentUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) authentication.getPrincipal();
        return carbonUserDetails;
    }
}
