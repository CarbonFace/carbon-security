package cn.carbonface.carbonsecurity.core.handler;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Classname: UserLoginFailureHandler
 * Description: handler for user login fail
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/3/17 18:33
 * @version V1.0
 */
@Component
@Slf4j
public class UserLoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                        AuthenticationException authenticationException) {
        ApiResult.response(httpServletResponse,new ApiResult<>(null,authenticationException.getMessage(), RetCode.USER_LOGIN_FAIL.getCode()));
    }
}
