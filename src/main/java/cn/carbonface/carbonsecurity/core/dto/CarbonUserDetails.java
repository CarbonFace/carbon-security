package cn.carbonface.carbonsecurity.core.dto;

import cn.carbonface.carboncommon.dto.userdto.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @Classname CarbonUserDetails
 * @Description CarbonFace userDetails for spring security
 * @Author CarbonFace <553127022 @ qq.com>
 * @Date 2021/3/17 17:35
 * @Version V1.0
 */
public class CarbonUserDetails extends User implements UserDetails {

    private static final long serialVersionUID = 1753124022099818053L;
    /**
     * 用户角色
     */
    private Collection<GrantedAuthority> authorities;

    /**
     * 账号是否过期
     */
    private boolean isAccountNonExpired = false;

    /**
     * 账号是否锁定
     */
    private boolean isAccountNonLocked = false;

    /**
     * 证书是否过期
     */
    private boolean isCredentialsNonExpired = false;

    /**
     * 账号是否有效
     */
    private boolean isEnabled = true;

    /**
     * 登陆的IP地址
     */
    private String ip;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }



    @Override
    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }


    public void setAuthorities(Collection<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        isAccountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        isAccountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        isCredentialsNonExpired = credentialsNonExpired;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

}
