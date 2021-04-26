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
 * @Description jwt authentication filter which is functioning as internal filter for security system
 *              which is mainly do the pre check and operations for token
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
                // judge whether the current token is expired
                if (TokenUtil.isExpiration(expiration)) {
                    // if the current token is expired, add the token to the black list
                    TokenUtil.addBlackList(token);
                    // judge whether the current token is within the valid time
                    String validTime = TokenUtil.getRefreshTimeByToken(token);
                    if (TokenUtil.isValid(validTime)) {
                        // if the token is within the valid time, refresh the token, lay a new one and replaced the old one in the header
                        String newToke = TokenUtil.refreshAccessToken(token);
                        TokenUtil.deleteRedisToken(token);
                        TokenUtil.setTokenInfo(newToke, username, ip);
                        response.setHeader(JWTConfig.tokenHeader, newToke);
                        log.info("用户{}的Token已过期，但为超过刷新时间，已刷新", username);
                        token = newToke;
                    } else {
                        log.info("用户{}的Token已过期且超过刷新时间，不予刷新", username);
                        // if not within the valid time add to the black list
                        TokenUtil.addBlackList(token);
                        TokenUtil.deleteRedisToken(token);
                        ApiResult.response(response,new ApiResult(RetCode.USER_LOGIN_EXPIRED));
                        return;
                    }
                }
                CarbonUserDetails carbonUserDetails = TokenUtil.parseAccessToken(token);
                if (carbonUserDetails != null) {
                    if (ip !=null && !ip.equals(carbonUserDetails.getIp())) {
                        log.info("用户{}请求IP与Token中IP信息不一致", username);
                        // if the ip address changed and front page brings the same token for request, add to the black list
                        TokenUtil.addBlackList(token);
                        TokenUtil.deleteRedisToken(token);
                        ApiResult.response(response,new ApiResult(null,"可能存在IP伪造风险",RetCode.USER_LOGIN_EXPIRED));
                        return;
                    }
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            carbonUserDetails, carbonUserDetails.getId(), carbonUserDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    TokenUtil.extendExpiration(token);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
