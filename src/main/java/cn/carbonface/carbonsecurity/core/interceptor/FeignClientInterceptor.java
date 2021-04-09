package cn.carbonface.carbonsecurity.core.interceptor;

import cn.carbonface.carbonsecurity.core.constants.FeignConstant;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * @Classname AnnotationInterceptor
 * @Description Feign interceptor used for header loss solve as the internal invoke between services among the CarbonFace Cloud
 *              which making the feign client invokes between services brings the correct header FEIGN_HEADER_NAME and correct
 *              value FEIGN_HEADER_VALUE to pass the authorization automatically and marks the request as feign invoke as well
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/28 15:16:22
 * @Version V1.0
 */
@Slf4j
@Component
public class FeignClientInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate requestTemplate) {
        requestTemplate.header(FeignConstant.FEIGN_HEADER_NAME,FeignConstant.FEIGN_HEADER_VALUE);
    }
}
