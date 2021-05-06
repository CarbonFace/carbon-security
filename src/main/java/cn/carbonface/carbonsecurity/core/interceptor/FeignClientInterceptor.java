package cn.carbonface.carbonsecurity.core.interceptor;

import cn.carbonface.carboncommon.tools.HttpUtil;
import cn.carbonface.carbonsecurity.core.config.JWTConfig;
import cn.carbonface.carbonsecurity.core.constants.FeignConstant;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

/**
 * Classname: AnnotationInterceptor
 * Description: Feign interceptor used for header loss solve as the internal invoke between services among the CarbonFace Cloud
 *              which making the feign client invokes between services brings the correct header FEIGN_HEADER_NAME and correct
 *              value FEIGN_HEADER_VALUE to pass the authorization automatically and marks the request as feign invoke as well
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/3/28 15:16:22
 * @version V1.0
 */
@Slf4j
@Component
public class FeignClientInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate requestTemplate) {
        requestTemplate.header(FeignConstant.FEIGN_HEADER_NAME,FeignConstant.FEIGN_HEADER_VALUE);
        HttpServletRequest request = HttpUtil.getRequest();
        HttpServletResponse response = HttpUtil.getResponse();
        Enumeration<String> headersEnum = request.getHeaderNames();
        while (headersEnum.hasMoreElements()){
            String headerName = headersEnum.nextElement();
            String header = request.getHeader(headerName);
            requestTemplate.header(headerName,header);
        }
        String token = response.getHeader(JWTConfig.tokenHeader);
        token = token==null?request.getHeader(JWTConfig.tokenHeader):token;
        if (token !=null){
            requestTemplate.header(JWTConfig.tokenHeader,token);
            log.info("token transferred in the RequestInterceptor");
        }

    }
}
