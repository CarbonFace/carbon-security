package cn.carbonface.carbonsecurity.core.handler;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import cn.carbonface.carboncommon.tools.HttpUtil;
import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.tools.TokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Classname UserLoginSuccessHandler
 * @Description handler when user login success
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/17 18:28
 * @Version V1.0
 */
@Component
@Slf4j
public class UserLoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) authentication.getPrincipal();
        String ip = HttpUtil.getIpAddress(httpServletRequest);
        carbonUserDetails.setIp(ip);
        String token = TokenUtil.layToken(carbonUserDetails);
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("token", token);
        // 保存Token信息到Redis中
        TokenUtil.setTokenInfo(token, carbonUserDetails.getUsername(), ip);
        log.info("用户{}登录成功，Token信息已保存到Redis", carbonUserDetails.getUsername());
        ApiResult.response(httpServletResponse,new ApiResult(RetCode.USER_LOGIN).token(token));
    }
}
