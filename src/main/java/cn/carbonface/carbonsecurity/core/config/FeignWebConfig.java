/*
 * Copyright (c) 2021. by CarbonFce
 */

package cn.carbonface.carbonsecurity.core.config;

import cn.carbonface.carbonsecurity.core.interceptor.FeignOnlyInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Classname FeignWebConfig
 * @Description TODO
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/4/8 16:40
 * @Version V1.0
 */
@Component
public class FeignWebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new FeignOnlyInterceptor());
    }
}