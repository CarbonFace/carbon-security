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
     * user authorities
     */
    private Collection<GrantedAuthority> authorities;

    /**
     * if the account expired
     */
    private boolean isAccountNonExpired = false;

    /**
     * if the account locked (not in the early access in CarboonFace Cloud)
     */
    private boolean isAccountNonLocked = false;

    /**
     * if the credentials expired (not in the early access in CarboonFace Cloud)
     */
    private boolean isCredentialsNonExpired = false;

    /**
     * if the account is enabled (not in the early access in CarboonFace Cloud)
     */
    private boolean isEnabled = true;

    /**
     * ip address
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
