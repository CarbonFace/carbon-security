package cn.carbonface.carbonsecurity.core;

import cn.carbonface.carbonsecurity.core.dto.CarbonUserDetails;
import cn.carbonface.carbonsecurity.core.service.CarbonUserDetailsService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @Classname UserAuthenticationProvider
 * @Description TODO
 * @Author CarbonFace <553127022@qq.com>
 * @Date 2021/3/31 11:05
 * @Version V1.0
 */
@Component
public class UserAuthenticationProvider implements AuthenticationProvider {

    private final CarbonUserDetailsService userDetailsService;

    public UserAuthenticationProvider(CarbonUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials(); // 获取密码
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) userDetailsService.loadUserByUsername(username);
        if (carbonUserDetails == null){
            throw new UsernameNotFoundException("用户不存在");
        }
        if (!new BCryptPasswordEncoder().matches(password, carbonUserDetails.getPassword())) {
            throw new BadCredentialsException("用户名或密码错误");
        }

        return new UsernamePasswordAuthenticationToken(carbonUserDetails,password,carbonUserDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
