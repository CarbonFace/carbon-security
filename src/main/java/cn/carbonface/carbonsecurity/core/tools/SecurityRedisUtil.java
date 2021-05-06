/*
 * Copyright (c) 2021. by CarbonFce
 */

package cn.carbonface.carbonsecurity.core.tools;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.data.redis.connection.RedisConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.concurrent.TimeUnit;

/**
 * Classname: SecurityRedisUtil
 * Description: Special Security RedisUtil which is only use for security redis operation and use a separate redis database
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/4/8 10:02
 * @version V1.0
 */
@Component
@Slf4j
public class SecurityRedisUtil {

    public static final int SECURITY_REDIS_DATABASE = 7;

    public static StringRedisTemplate redisTemplate;

    public SecurityRedisUtil(RedisProperties redisProperties) {
        RedisConfiguration securityRedisConfiguration = initSecurityRedisConfiguration(redisProperties);
        GenericObjectPoolConfig genericObjectPoolConfig = initPoolConfig(redisProperties);
        LettuceConnectionFactory securityConnectionFactory = initRedisFactory(securityRedisConfiguration, genericObjectPoolConfig, redisProperties);
        redisTemplate = new StringRedisTemplate();
        redisTemplate.setConnectionFactory(securityConnectionFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashValueSerializer(new Jackson2JsonRedisSerializer<>(Object.class));
        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(Object.class));
        redisTemplate.afterPropertiesSet();
    }
    private LettuceConnectionFactory initRedisFactory(RedisConfiguration securityRedisConfiguration, GenericObjectPoolConfig genericObjectPoolConfig,RedisProperties redisProperties) {
        //redis客户端配置
        LettucePoolingClientConfiguration.LettucePoolingClientConfigurationBuilder
                builder =  LettucePoolingClientConfiguration.builder().
                commandTimeout(redisProperties.getTimeout());
        builder.shutdownTimeout(redisProperties.getLettuce().getShutdownTimeout());
        builder.poolConfig(genericObjectPoolConfig);
        LettuceClientConfiguration lettuceClientConfiguration = builder.build();
        LettuceConnectionFactory securityConnectionFactory = new LettuceConnectionFactory((RedisStandaloneConfiguration)securityRedisConfiguration,lettuceClientConfiguration);
        securityConnectionFactory.afterPropertiesSet();
        return securityConnectionFactory;
    }

    private GenericObjectPoolConfig initPoolConfig(RedisProperties redisProperties) {
        //连接池配置
        GenericObjectPoolConfig genericObjectPoolConfig =
                new GenericObjectPoolConfig();
        genericObjectPoolConfig.setMaxIdle(redisProperties.getLettuce().getPool().getMaxIdle());
        genericObjectPoolConfig.setMinIdle(redisProperties.getLettuce().getPool().getMinIdle());
        genericObjectPoolConfig.setMaxTotal(redisProperties.getLettuce().getPool().getMaxActive());
        genericObjectPoolConfig.setMaxWaitMillis(redisProperties.getLettuce().getPool().getMaxWait().toMillis());
        return genericObjectPoolConfig;
    }

    private RedisConfiguration initSecurityRedisConfiguration(RedisProperties redisProperties) {
        String hostName = redisProperties.getHost();
        int port = redisProperties.getPort();
        String password = redisProperties.getPassword();
        RedisConfiguration redisConfiguration = new RedisStandaloneConfiguration(hostName,port);
        ((RedisStandaloneConfiguration) redisConfiguration).setDatabase(SECURITY_REDIS_DATABASE);
        ((RedisStandaloneConfiguration) redisConfiguration).setPassword(password);
        return redisConfiguration;
    }

    public static void expire(String key, long time) {
        if (time > 0) {
            redisTemplate.expire(key, time, TimeUnit.SECONDS);
        }
    }

    /**
     * 判断key是否存在
     *
     * @param key 键
     * @return true 存在 false不存在
     */
    public static boolean hasKey(String key) {
        return redisTemplate.hasKey(key);
    }

    /**
     * 判断key和hasKey下是否有值
     *
     * @param key
     * @param hasKey
     */
    public static Boolean hasKey(String key, String hasKey) {
        return redisTemplate.opsForHash().hasKey(key, hasKey);
    }

    /**
     * 删除缓存
     *
     * @param key 可以传一个值 或多个
     */
    @SuppressWarnings("unchecked")
    public static void del(String... key) {
        if (key != null && key.length > 0) {
            if (key.length == 1) {
                redisTemplate.delete(key[0]);
            } else {
                redisTemplate.delete((Collection<String>) CollectionUtils.arrayToList(key));
            }
        }
    }

    /**
     * HashGet
     *
     * @param key  键 不能为null
     * @param item 项 不能为null
     * @return 值
     */
    public static Object hGet(String key, String item) {
        return redisTemplate.opsForHash().get(key, item);
    }
    /**
     * 向一张hash表中放入数据,如果不存在将创建
     *
     * @param key   键
     * @param item  项
     * @param value 值
     */

    public static void hSet(String key, String item, Object value) {
        redisTemplate.opsForHash().put(key, item, value);
    }

    /**
     * 向一张hash表中放入数据,如果不存在将创建
     *
     * @param key   键
     * @param item  项
     * @param value 值
     * @param time  时间(秒) 注意:如果已存在的hash表有时间,这里将会替换原有的时间
     */
    public static void hSet(String key, String item, Object value, long time) {
        redisTemplate.opsForHash().put(key, item, value);
        if (time > 0) {
            expire(key, time);
        }
    }
}
