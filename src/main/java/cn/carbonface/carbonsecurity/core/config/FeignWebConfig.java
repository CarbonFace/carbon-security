/*
 * Copyright (c) 2021. by CarbonFce
 */

package cn.carbonface.carbonsecurity.core.config;

import cn.carbonface.carbonsecurity.core.interceptor.FeignOnlyInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Classname: FeignWebConfig
 * Description: FeignWebConfig is the configuration for control the feign only controllers that can only be invoked by
 *              feign clients, it is worked by introduce the FeignOnlyInterceptor to the InterceptorRegistry from WebMvcConfigurer
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/4/8 16:40
 * @version V1.0
 */
@Component
public class FeignWebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new FeignOnlyInterceptor());
    }
}