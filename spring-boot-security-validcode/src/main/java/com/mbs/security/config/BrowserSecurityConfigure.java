package com.mbs.security.config;

import com.mbs.security.filter.ValidateCodeFilter;
import com.mbs.security.handler.MyAuthenticationFailureHandler;
import com.mbs.security.handler.MyAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/23 17:16
 */
@Configuration
public class BrowserSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Autowired
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 添加验证码校验过滤器
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin()
                // 登录页
//                .loginPage("/login")
                .loginPage("/authentication/require")
                // 登录处理路径
                .loginProcessingUrl("/login")
                // 登录成功处理逻辑
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
                .and()
                // 授权配置
                .authorizeRequests()
                // 无需认证匹配
                .antMatchers("/login",
                        "/authentication/require",
                        "/code/image").permitAll()
                // 所有请求
                .anyRequest()
                // 都需要认证
                .authenticated()
                .and().csrf().disable();

    }
}
