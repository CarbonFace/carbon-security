package cn.carbonface.carbonsecurity.core.interceptor;

import cn.carbonface.carbonsecurity.core.constants.FeignConstant;
import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import cn.carbonface.carboncommon.exception.CarbonException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * @Classname AnnotationInterceptor
 * @Description Feign interceptor for feign client invoking with annotation @FeignOnly that only can invoke via feign
 *              clients which is not expose to the gateway and nginx
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/26 18:00
 * @Version V1.0
 */
@Slf4j
@Component
public class FeignOnlyInterceptor implements HandlerInterceptor {


    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws CarbonException {
        boolean feignOnly = feignOnly(request,handler);
        if (feignOnly){
            throw new CarbonException(RetCode.FEIGN_ONLY);
        }else{
            return true;
        }
    }

    private boolean feignOnly(HttpServletRequest request, Object handler) {
        FeignOnly feignOnly = null;
        String feignHeader = request.getHeader(FeignConstant.FEIGN_HEADER_NAME);
        boolean feignInvoke = FeignConstant.FEIGN_HEADER_VALUE.equals(feignHeader);//maybe I just consider this before enter this method and interceptor would be faster?
        if (handler instanceof HandlerMethod){
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            Method method = handlerMethod.getMethod();
            feignOnly = method.getAnnotation(FeignOnly.class);
        }else if (handler instanceof ResourceHttpRequestHandler){
            ApplicationContext applicationContext = ((ResourceHttpRequestHandler) handler).getApplicationContext();
            log.warn("WARN!THERE IS A TYPE WRONG WHICH NEED SOME ATTENTION!");
        }

        return feignOnly != null && !feignInvoke;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        if (ex != null){
            ex.printStackTrace();
            ApiResult.error(ex.getMessage());
        }
    }
}
