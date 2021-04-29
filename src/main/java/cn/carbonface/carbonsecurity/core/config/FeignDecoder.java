package cn.carbonface.carbonsecurity.core.config;

import cn.carbonface.carboncommon.dto.ApiResult;
import cn.carbonface.carboncommon.dto.RetCode;
import com.alibaba.fastjson.JSON;
import feign.FeignException;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import sun.reflect.generics.reflectiveObjects.ParameterizedTypeImpl;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * Classname: FeignDecoder
 * Description: TODO
 *
 * @author carbonface <553127022@qq.com>
 * Date: 2021/4/29 15:23
 * @version v1.0
 */
@Component
@Slf4j
public class FeignDecoder implements Decoder{

    @Override
    public Object decode(Response response, Type type) throws IOException, DecodeException, FeignException {
        Response.Body body = response.body();
        if (body == null){
            return null;
        }
        String bodyStr = Util.toString(response.body().asReader(Util.UTF_8));
        //parse json to ApiResult
        String apiResultRegx = ApiResult.class.getTypeName() +
                "(<([a-zA-Z_$][a-zA-Z\\d_$]*\\.)*[a-zA-Z_$][a-zA-Z\\d_$]*>)*";
        if (ApiResult.class.getTypeName().matches(apiResultRegx)){
            ApiResult<?> result = JSON.parseObject(bodyStr, type);
            int retCode = result.getRetCode();
            if (retCode != RetCode.SUCCESS.getCode()){
                throw new DecodeException(retCode,result.getMsg(),response.request());
            }
            throw new DecodeException(retCode,result.getMsg(),response.request());
//            return result;
        }else{
            throw new DecodeException(RetCode.INTERNAL_ERROR.getCode(),RetCode.INTERNAL_ERROR.getMessage(),response.request());
        }
    }

}
