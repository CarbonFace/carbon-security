/*
 * Copyright (c) 2021. by CarbonFce
 */

package cn.carbonface.carbonsecurity.core.interceptor;

import java.lang.annotation.*;

/**
 * Classname: NoAuth
 * Description: NoAuth annotation which allowed the service recognized controllers as no authorization need controller,
 *              with the 'CarbonSecurityConfig' imported, the service will automatically scan the controllers which is annotated by
 *              '@NoAuth' annotation and add them to security white list
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/4/6 16:38
 * @version V1.0
 */
@Target({ElementType.METHOD,ElementType.TYPE,ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface NoAuth {
}
