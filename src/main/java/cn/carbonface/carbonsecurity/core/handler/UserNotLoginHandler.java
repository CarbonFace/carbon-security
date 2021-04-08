package cn.carbonface.carbonsecurity.core.handler;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Classname UserNotLoginHandler
 * @Description TODO
 * @Author CarbonFace   <553127022@qq.com>
 * @Date 2021/3/17 18:27
 * @Version V1.0
 */
@Component
@Slf4j
public class UserNotLoginHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                         AuthenticationException authenticationException) throws IOException, ServletException {
        ApiResult.response(httpServletResponse,new ApiResult(authenticationException.getMessage(), RetCode.USER_NOT_LOGIN));
    }
}
