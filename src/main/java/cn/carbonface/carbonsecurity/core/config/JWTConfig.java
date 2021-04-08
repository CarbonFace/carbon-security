package cn.carbonface.carbonsecurity.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * @Classname JWTConfig
 * @Description JWTConfig
 * @Author CarbonFace   <553127022@qq.com>
 * @Date 2021/3/17 17:42
 * @Version V1.0
 */
@ConfigurationProperties(prefix = "jwt")
@Component
@SuppressWarnings("static-access")
public class JWTConfig {

    /**
     * 密匙Key
     */

    public static String secret;

    /**
     * HeaderKey
     */

    public static String tokenHeader;

    /**
     * Token前缀
     */

    public static String tokenPrefix;

    /**
     * 过期时间
     */

    public static Integer expiration;

    /**
     * 配置白名单
     */

    public static String antMatchers;

    /**
     * 有效时间
     */
    public static Integer refreshTime;
    /**
     * 将过期时间单位换算成毫秒
     *
     * @param expiration 过期时间，单位秒
     */
    public void setExpiration(Integer expiration) {
        this.expiration = expiration * 1000;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setTokenHeader(String tokenHeader) {
        this.tokenHeader = tokenHeader;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix + " ";
    }

    public void setAntMatchers(String antMatchers) {
        this.antMatchers = antMatchers;
    }

    public void setRefreshTime(Integer refreshTime) {
        this.refreshTime = refreshTime * 24 * 60 * 60 * 1000;
    }
}
