package cn.carbonface.carbonsecurity.core.interceptor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @Classname FeignOnly
 * @Description annotation which used to controller the controller which is only used for feign client but not http request
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/26 18:11
 * @Version V1.0
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@NoAuth
public @interface FeignOnly {
}
