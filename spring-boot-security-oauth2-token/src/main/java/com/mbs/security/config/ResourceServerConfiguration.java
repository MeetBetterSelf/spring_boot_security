package com.mbs.security.config;

import com.mbs.security.handler.MyAuthenticationFailureHandler;
import com.mbs.security.handler.MyAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/26 17:09
 */
//@Order(2)
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Autowired
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                // 表单登录
                .formLogin()
                // 登录处理路径
                .loginProcessingUrl("/login")
                // 登录成功处理逻辑
                .successHandler(myAuthenticationSuccessHandler)
                // 登录失败处理逻辑
                .failureHandler(myAuthenticationFailureHandler)
                .and()
                // 授权配置
                .authorizeRequests()
                // 所有请求
                .anyRequest()
                // 都需要认证
                .authenticated()
                .and()
                // 禁用csrf
                .csrf().disable();
    }
}
