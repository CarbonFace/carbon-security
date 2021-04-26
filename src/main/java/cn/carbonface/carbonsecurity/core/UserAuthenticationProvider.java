package cn.carbonface.carbonsecurity.core;

import cn.carbonface.carboncommon.dto.RetCode;
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
 * classname UserAuthenticationProvider
 * description user authentication action determined
 * @author CarbonFace <553127022@qq.com>
 * date 2021/3/31 11:05
 * @version V1.0
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
        String password = (String) authentication.getCredentials(); // acquire password
        CarbonUserDetails carbonUserDetails = (CarbonUserDetails) userDetailsService.loadUserByUsername(username);
        if (carbonUserDetails == null){
            throw new UsernameNotFoundException(RetCode.USER_ACCOUNT_NOT_EXIST.getMessage());
        }
        if (!new BCryptPasswordEncoder().matches(password, carbonUserDetails.getPassword())) {
            throw new BadCredentialsException(RetCode.USER_CREDENTIALS_ERROR.getMessage());
        }

        return new UsernamePasswordAuthenticationToken(carbonUserDetails,password,carbonUserDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
