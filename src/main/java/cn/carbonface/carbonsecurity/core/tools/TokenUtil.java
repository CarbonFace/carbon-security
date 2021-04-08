package cn.carbonface.carbonsecurity.core.tools;



import cn.carbonface.carbonsecurity.core.config.JWTConfig;
import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.service.CarbonUserDetailsService;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * @Classname TokenUtil
 * @Description TokenUtil
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/17 17:54
 * @Version V1.0
 */
@Component
@Slf4j
public class TokenUtil {

    private static CarbonUserDetailsService carbonUserDetailsService;
    private static final DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public TokenUtil(CarbonUserDetailsService carbonUserDetailsService) {
        TokenUtil.carbonUserDetailsService = carbonUserDetailsService;
    }

    /**
     * 创建Token
     *
     * @param carbonUserDetails 用户信息
     * @return
     */
    public static String layToken(CarbonUserDetails carbonUserDetails) {
        String token = Jwts.builder().setId(// 设置JWT
                carbonUserDetails.getId().toString()) // 用户Id
                .setSubject(carbonUserDetails.getUsername()) // 主题
                .setIssuedAt(new Date()) // 签发时间
                .setIssuer("CarbonFace") // 签发者
                .setExpiration(new Date(System.currentTimeMillis() + JWTConfig.expiration)) // 过期时间
                .signWith(SignatureAlgorithm.HS512, JWTConfig.secret) // 签名算法、密钥
                .claim("authorities", JSON.toJSONString(carbonUserDetails.getAuthorities())) // 自定义其他属性，如用户组织机构ID，用户所拥有的角色，用户权限信息等
                .claim("ip",carbonUserDetails.getIp())  //设置ip
                .compact();
        return JWTConfig.tokenPrefix + token;
    }

    /**
     * 刷新Token
     *
     * @param oldToken 过期但未超过刷新时间的Token
     * @return
     */
    public static String refreshAccessToken(String oldToken) {
        String username = getUserNameByToken(oldToken);
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) carbonUserDetailsService.loadUserByUsername(username);
        carbonUserDetails.setIp(getIpByToken(oldToken));
        return layToken(carbonUserDetails);
    }


    /**
     * 解析Token
     *
     * @param token Token信息
     * @return
     */
    public static CarbonUserDetails parseAccessToken(String token) {
        CarbonUserDetails carbonUserDetails = null;
        if (StringUtils.hasLength(token)) {
            try {
                // 去除JWT前缀
                token = token.substring(JWTConfig.tokenPrefix.length());
                // 解析Token
                Claims claims = Jwts.parser().setSigningKey(JWTConfig.secret).parseClaimsJws(token).getBody();
                // 获取用户信息
                carbonUserDetails = new CarbonUserDetails();
                carbonUserDetails.setId(Long.parseLong(claims.getId()));
                carbonUserDetails.setUsername(claims.getSubject());
                // 获取角色
                Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
                String authority = claims.get("authorities").toString();
                if (StringUtils.hasLength(authority)) {
                    List<Map<String, String>> authorityList = JSON.parseObject(authority,
                            new TypeReference<List<Map<String, String>>>() {
                            });
                    for (Map<String, String> role : authorityList) {
                        if (!role.isEmpty()) {
                            authorities.add(new SimpleGrantedAuthority(role.get("authority")));
                        }
                    }
                }
                carbonUserDetails.setAuthorities(authorities);
            } catch (Exception e) {
                log.error("解析Token异常：" + e);
            }
        }
        return carbonUserDetails;
    }

    /**
     * 保存Token信息到Redis中
     *
     * @param token    Token信息
     * @param username 用户名
     * @param ip       IP
     */
    public static void setTokenInfo(String token, String username, String ip) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());

            Integer refreshTime = JWTConfig.refreshTime;
            LocalDateTime localDateTime = LocalDateTime.now();
            SecurityRedisUtil.hSet(token, "username", username, refreshTime);
            SecurityRedisUtil.hSet(token, "ip", ip, refreshTime);
            SecurityRedisUtil.hSet(token, "refreshTime",
                    dateFormatter.format(localDateTime.plus(JWTConfig.refreshTime, ChronoUnit.MILLIS)), refreshTime);
            SecurityRedisUtil.hSet(token, "expiration", dateFormatter.format(localDateTime.plus(JWTConfig.expiration, ChronoUnit.MILLIS)),
                    refreshTime);
        }
    }

    /**
     * 将Token放到黑名单中
     *
     * @param token Token信息
     */
    public static void addBlackList(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            SecurityRedisUtil.hSet("blackList", token, dateFormatter.format(LocalDateTime.now()));
        }
    }

    /**
     * Redis中删除Token
     *
     * @param token Token信息
     */
    public static void deleteRedisToken(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            SecurityRedisUtil.del(token);
        }
    }

    /**
     * 判断当前Token是否在黑名单中
     *
     * @param token Token信息
     */
    public static boolean isBlackList(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hasKey("blackList", token);
        }
        return false;
    }

    /**
     * 是否过期
     *
     * @param expiration 过期时间，字符串
     * @return 过期返回True，未过期返回false
     */
    public static boolean isExpiration(String expiration) {
        LocalDateTime expirationTime = LocalDateTime.parse(expiration, dateFormatter);
        LocalDateTime localDateTime = LocalDateTime.now();
        if (localDateTime.compareTo(expirationTime) > 0) {
            return true;
        }
        return false;
    }

    /**
     * 是否有效
     *
     * @param refreshTime 刷新时间，字符串
     * @return 有效返回True，无效返回false
     */
    public static boolean isValid(String refreshTime) {
        LocalDateTime validTime = LocalDateTime.parse(refreshTime, dateFormatter);
        LocalDateTime localDateTime = LocalDateTime.now();
        if (localDateTime.compareTo(validTime) > 0) {
            return false;
        }
        return true;
    }

    /**
     * 检查Redis中是否存在Token
     *
     * @param token Token信息
     * @return
     */
    public static boolean hasToken(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hasKey(token);
        }
        return false;
    }

    /**
     * 从Redis中获取过期时间
     *
     * @param token Token信息
     * @return 过期时间，字符串
     */
    public static String getExpirationByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "expiration").toString();
        }
        return null;
    }

    /**
     * 从Redis中获取刷新时间
     *
     * @param token Token信息
     * @return 刷新时间，字符串
     */
    public static String getRefreshTimeByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "refreshTime").toString();
        }
        return null;
    }

    /**
     * 从Redis中获取用户名
     *
     * @param token Token信息
     * @return
     */
    public static String getUserNameByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "username").toString();
        }
        return null;
    }

    /**
     * 从Redis中获取IP
     *
     * @param token Token信息
     * @return
     */
    public static String getIpByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // 去除JWT前缀
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "ip").toString();
        }
        return null;
    }

}