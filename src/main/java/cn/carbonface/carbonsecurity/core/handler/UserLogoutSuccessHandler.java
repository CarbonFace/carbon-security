package cn.carbonface.carbonsecurity.core.handler;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import cn.carbonface.carbonsecurity.core.config.JWTConfig;
import cn.carbonface.carbonsecurity.core.tools.TokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Classname UserLogoutSuccessHandler
 * @Description handler for user logout
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/17 18:33
 * @Version V1.0
 */
@Component
@Slf4j
public class UserLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                        Authentication authentication) {
        String token = httpServletRequest.getHeader(JWTConfig.tokenHeader);
        TokenUtil.addBlackList(token);
        log.info("用户{}登出成功，Token信息已保存到Redis的黑名单中", TokenUtil.getUserNameByToken(token));
        ApiResult.response(httpServletResponse,new ApiResult<>(RetCode.USER_LOGOUT));
    }
}
