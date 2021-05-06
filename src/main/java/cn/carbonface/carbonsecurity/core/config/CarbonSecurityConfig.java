package cn.carbonface.carbonsecurity.core.config;


import cn.carbonface.carbonsecurity.core.interceptor.NoAuth;
import cn.carbonface.carbonsecurity.core.handler.*;
import cn.carbonface.carbonsecurity.core.UserAuthenticationProvider;
import cn.carbonface.carbonsecurity.core.UserPermissionEvaluator;
import cn.carbonface.carbonsecurity.core.filter.JWTAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Map;
import java.util.Set;

/**
 * Classname: SecurityConfig
 * Description: TODO
 * @author CarbonFace <553127022@qq.com>
 * Date: 2021/3/18 17:09
 * @version V1.0
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class CarbonSecurityConfig extends WebSecurityConfigurerAdapter {

    private final RequestMappingHandlerMapping requestMappingHandlerMapping;

    public static final int SECURITY_REDIS_BASE = 3;
    /**
     * 无权限处理类
     */
    private final UserAccessDeniedHandler userAccessDeniedHandler;

    /**
     * 用户未登录处理类
     */
    private final UserNotLoginHandler userNotLoginHandler;

    /**
     * 用户登录成功处理类
     */
    private final UserLoginSuccessHandler userLoginSuccessHandler;

    /**
     * 用户登录失败处理类
     */
    private final UserLoginFailureHandler userLoginFailureHandler;

    /**
     * 用户登出成功处理类
     */
    private final UserLogoutSuccessHandler userLogoutSuccessHandler;

    /**
     * 用户登录验证
     */
    private final UserAuthenticationProvider userAuthenticationProvider;

    /**
     * 用户权限注解
     */
    private final UserPermissionEvaluator userPermissionEvaluator;

    public CarbonSecurityConfig(RequestMappingHandlerMapping requestMappingHandlerMapping, UserAccessDeniedHandler userAccessDeniedHandler, UserNotLoginHandler userNotLoginHandler, UserLoginSuccessHandler userLoginSuccessHandler, UserLoginFailureHandler userLoginFailureHandler, UserLogoutSuccessHandler userLogoutSuccessHandler, UserAuthenticationProvider userAuthenticationProvider, UserPermissionEvaluator userPermissionEvaluator) {
        this.requestMappingHandlerMapping = requestMappingHandlerMapping;
        this.userAccessDeniedHandler = userAccessDeniedHandler;
        this.userNotLoginHandler = userNotLoginHandler;
        this.userLoginSuccessHandler = userLoginSuccessHandler;
        this.userLoginFailureHandler = userLoginFailureHandler;
        this.userLogoutSuccessHandler = userLogoutSuccessHandler;
        this.userAuthenticationProvider = userAuthenticationProvider;
        this.userPermissionEvaluator = userPermissionEvaluator;
    }

    /**
     * 加密方式
     *
     * @return
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 注入自定义PermissionEvaluator
     *
     * @return
     */
    @Bean
    public DefaultWebSecurityExpressionHandler userSecurityExpressionHandler() {
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setPermissionEvaluator(userPermissionEvaluator);
        return handler;
    }

    /**
     * 用户登录验证
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(userAuthenticationProvider);
    }

    /**
     * 安全权限配置
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        feignOnlyPermit(http);
        http.authorizeRequests() // 权限配置
                .antMatchers(JWTConfig.antMatchers.split(",")).permitAll()// 获取白名单（不进行权限验证）
                .anyRequest().authenticated() // 其他的需要登陆后才能访问
                .and().httpBasic().authenticationEntryPoint(userNotLoginHandler) // 配置未登录处理类
                .and().formLogin().loginProcessingUrl("/login/submit")// 配置登录URL
                .successHandler(userLoginSuccessHandler) // 配置登录成功处理类
                .failureHandler(userLoginFailureHandler) // 配置登录失败处理类
                .and().logout().logoutUrl("/logout/submit")// 配置登出地址
                .logoutSuccessHandler(userLogoutSuccessHandler) // 配置用户登出处理类
                .and().exceptionHandling().accessDeniedHandler(userAccessDeniedHandler)// 配置没有权限处理类
                .and().cors()// 开启跨域
                .and().csrf().disable(); // 禁用跨站请求伪造防护
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 禁用session（使用Token认证）
        http.headers().cacheControl(); // 禁用缓存
        http.addFilter(new JWTAuthenticationFilter(authenticationManager()));
    }

    private void feignOnlyPermit(HttpSecurity http) throws Exception {
        Map<RequestMappingInfo, HandlerMethod> handlerMethods = requestMappingHandlerMapping.getHandlerMethods();
        registerAllFeignOnlyController(handlerMethods,http);
    }

    private void registerAllFeignOnlyController(Map<RequestMappingInfo, HandlerMethod> controllers, HttpSecurity http)throws Exception  {
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : controllers.entrySet()) {
            RequestMappingInfo requestMappingInfo = entry.getKey();
            HandlerMethod handlerMethod = entry.getValue();
            if (handlerMethod.getMethodAnnotation(NoAuth.class) != null) {
                Set<String> patterns = requestMappingInfo.getPatternsCondition().getPatterns();
                for (String pattern : patterns) {
                    log.info("url ->" + pattern + " added to the white list of carbon-security");
                    http.authorizeRequests().antMatchers(pattern).permitAll();
                }
            }
        }
    }
}
