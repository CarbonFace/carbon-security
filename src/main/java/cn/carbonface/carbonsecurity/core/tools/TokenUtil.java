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
 * @Description TokenUtil used for security service
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
     * lay Token
     *
     * @param carbonUserDetails user details
     * @return
     */
    public static String layToken(CarbonUserDetails carbonUserDetails) {
                                    // set JWT
        String token = Jwts.builder().setId(
                carbonUserDetails.getId().toString()) // user id
                .setSubject(carbonUserDetails.getUsername()) // subject
                .setIssuedAt(new Date()) // issued time
                .setIssuer("CarbonFace") // issuer
                .setExpiration(new Date(System.currentTimeMillis() + JWTConfig.expiration)) // expire time
                .signWith(SignatureAlgorithm.HS512, JWTConfig.secret) // signature algorithm and secret key
                .claim("authorities", JSON.toJSONString(carbonUserDetails.getAuthorities())) // user authorities
                .claim("ip",carbonUserDetails.getIp())  //set ip address
                .compact();
        return JWTConfig.tokenPrefix + token;
    }

    /**
     * refresh Token
     *
     * @param oldToken refresh token time which is expired but not reach the dead time
     * @return
     */
    public static String refreshAccessToken(String oldToken) {
        String username = getUserNameByToken(oldToken);
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) carbonUserDetailsService.loadUserByUsername(username);
        carbonUserDetails.setIp(getIpByToken(oldToken));
        return layToken(carbonUserDetails);
    }


    /**
     * parse Token
     * parse the token information
     * @param token
     * @return
     */
    public static CarbonUserDetails parseAccessToken(String token) {
        CarbonUserDetails carbonUserDetails = null;
        if (StringUtils.hasLength(token)) {
            try {
                //remove JWT prefix
                token = token.substring(JWTConfig.tokenPrefix.length());
                // parse Token
                Claims claims = Jwts.parser().setSigningKey(JWTConfig.secret).parseClaimsJws(token).getBody();
                // acquire user details
                carbonUserDetails = new CarbonUserDetails();
                carbonUserDetails.setId(Long.parseLong(claims.getId()));
                carbonUserDetails.setUsername(claims.getSubject());
                // acquire authorities
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
     * save token information to redis
     *
     * @param token    token
     * @param username username
     * @param ip       ip address
     */
    public static void setTokenInfo(String token, String username, String ip) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
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
     * add token into black list
     *
     * @param token Token
     */
    public static void addBlackList(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            SecurityRedisUtil.hSet("blackList", token, dateFormatter.format(LocalDateTime.now()));
        }
    }

    /**
     * delete token in redis
     *
     * @param token Token
     */
    public static void deleteRedisToken(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            SecurityRedisUtil.del(token);
        }
    }

    /**
     * judge whether the current token is in the blacklist
     *
     * @param token Token
     */
    public static boolean isBlackList(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hasKey("blackList", token);
        }
        return false;
    }

    /**
     * judge whether the current token is expired
     *
     * @param expiration expiration string
     * @return
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
     * judge whether the current token is valid
     *
     * @param refreshTime refreshTime string
     * @return
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
     * seek for the token in the redis
     *
     * @param token Token
     * @return
     */
    public static boolean hasToken(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hasKey(token);
        }
        return false;
    }

    /**
     * get the expire time of token in the redis
     *
     * @param token Token
     * @return
     */
    public static String getExpirationByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "expiration").toString();
        }
        return null;
    }

    /**
     * get the refresh time of token in redis
     *
     * @param token Token
     * @return
     */
    public static String getRefreshTimeByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "refreshTime").toString();
        }
        return null;
    }

    /**
     * get the username of the token in redis
     *
     * @param token Token
     * @return
     */
    public static String getUserNameByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "username").toString();
        }
        return null;
    }

    /**
     * get the ip address of the token from redis
     *
     * @param token Token
     * @return
     */
    public static String getIpByToken(String token) {
        if (StringUtils.hasLength(token)) {
            // remove JWT prefix
            token = token.substring(JWTConfig.tokenPrefix.length());
            return SecurityRedisUtil.hGet(token, "ip").toString();
        }
        return null;
    }

}