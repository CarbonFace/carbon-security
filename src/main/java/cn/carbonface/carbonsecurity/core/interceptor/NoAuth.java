/*
 * Copyright (c) 2021. by CarbonFce
 */

package cn.carbonface.carbonsecurity.core.interceptor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @Classname NoAuth
 * @Description TODO
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/4/6 16:38
 * @Version V1.0
 */
@Target({ElementType.METHOD,ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface NoAuth {
}
