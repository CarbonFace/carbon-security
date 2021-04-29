package cn.carbonface.carbonsecurity.core.handler;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Classname UserAccessDeniedHandler
 * @Description handler for user access denied
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/17 18:15
 * @Version V1.0
 */
@Component
@Slf4j
public class UserAccessDeniedHandler implements AccessDeniedHandler{

    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ApiResult.response(httpServletResponse,new ApiResult<>(null,accessDeniedException.getMessage(), RetCode.ACCESS_DENIED.getCode()));
    }
}
