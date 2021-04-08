package cn.carbonface.carbonsecurity.core.filter;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import cn.carbonface.carboncommon.tools.HttpUtil;
import cn.carbonface.carbonsecurity.core.config.JWTConfig;
import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.tools.TokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Classname JWTAuthenticationFilter
 * @Description TODO
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/31 16:35
 * @Version V1.0
 */
@Slf4j
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {


    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String token = request.getHeader(JWTConfig.tokenHeader);
        if (token != null && token.startsWith(JWTConfig.tokenPrefix)) {
            if (TokenUtil.isBlackList(token)) {
                ApiResult.response(response,new ApiResult(RetCode.USER_LOGIN_EXPIRED));
                return;
            }
            if (TokenUtil.hasToken(token)) {
                String ip = HttpUtil.getIpAddress(request);
                String expiration = TokenUtil.getExpirationByToken(token);
                String username = TokenUtil.getUserNameByToken(token);

                // 判断是否过期
                if (TokenUtil.isExpiration(expiration)) {
                    // 加入黑名单
                    TokenUtil.addBlackList(token);

                    // 是否在刷新期内
                    String validTime = TokenUtil.getRefreshTimeByToken(token);
                    if (TokenUtil.isValid(validTime)) {
                        // 刷新Token，重新存入请求头
                        String newToke = TokenUtil.refreshAccessToken(token);

                        // 删除旧的Token，并保存新的Token
                        TokenUtil.deleteRedisToken(token);
                        TokenUtil.setTokenInfo(newToke, username, ip);
                        response.setHeader(JWTConfig.tokenHeader, newToke);

                        log.info("用户{}的Token已过期，但为超过刷新时间，已刷新", username);
                        token = newToke;
                    } else {
                        log.info("用户{}的Token已过期且超过刷新时间，不予刷新", username);
                        // 加入黑名单
                        TokenUtil.addBlackList(token);
                        ApiResult.response(response,new ApiResult(RetCode.USER_LOGIN_EXPIRED));
                        return;
                    }
                }
                CarbonUserDetails carbonUserDetails = TokenUtil.parseAccessToken(token);
                if (carbonUserDetails != null) {
                    if (ip !=null && ip.equals(carbonUserDetails.getIp())) {
                        log.info("用户{}请求IP与Token中IP信息不一致", username);
                        // 加入黑名单
                        TokenUtil.addBlackList(token);
                        ApiResult.response(response,new ApiResult(null,"可能存在IP伪造风险",RetCode.USER_LOGIN_EXPIRED));
                        return;
                    }

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            carbonUserDetails, carbonUserDetails.getId(), carbonUserDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
