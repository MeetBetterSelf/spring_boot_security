package com.mbs.security.service.impl;

import com.mbs.security.model.entity.OpenUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/24 15:46
 */
@Service("userDetailService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // spring security oauth2
        OpenUserDetails userDetails = new OpenUserDetails();
        userDetails.setUsername(username);
        userDetails.setPassword(passwordEncoder.encode("123456"));
        userDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("user"));
        return userDetails;
    }
}