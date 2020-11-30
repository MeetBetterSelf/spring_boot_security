# Spring Boot Security

### 引用Spring Security
1.pom.xml 新增依赖
2.新建TestController

```
@RestController
public class TestController {
    @GetMapping("hello")
    public String hello() {
        return "hello spring security";
    }
}
```

3.启动访问 http://localhost:8080/hello
出现认证框，说明Spring引入Spring Security，会默认开启basic类型认证。

spring security 5.0版本默认开启的认证 类型是表单认证

### 基于表单认证

1.新建config目录BrowserSecurityConfigure

```
package com.mbs.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/23 17:16
 */
@Configuration
public class BrowserSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }
}

```

### 认证基本原理

Spring Security包含了众多过滤器，所有请求必须通过这些过滤器才能访问到资源。

UsernamePasswordAuthenticationFilter ：表单登录认证

BasicAuthenticationFilter：Http Basic登录认证

FilterSecurityInterceptor：拦截器



表单登录认证流程

UsernamePasswordAuthenticationFilter .attemptAuthentication()里调用

ProviderManager.authenticate()里获取相应的DaoAuthenticationProvider调用

AbstractUserDetailsAuthenticationProvider.authenticate()里的调用

DaoAuthenticationProvider.retrieveUser()里的getUserDetailsService().loadUserByUsername()

如果没有该用户会抛出UsernameNotFoundException，由ExceptionTranslationFilter过滤器捕获处理。

如果用户登录成功，由FilterSecurityInterceptor判断当前请求身份认证是否成功、是否具有相应权限。



### 自定义用户认证

自定义认证需要实现UserDetailsService接口，该接口只有一个loadUserByUsername方法。该方法返回一个UserDetails接口，所以需要自定义一个UserDetails的实现类或使用默认的User实现类。

1.实现用户信息自定义逻辑

创建UserDetailsServiceImpl

```
package com.mbs.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
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
        User user = new User(username,passwordEncoder.encode("123456"),
                AuthorityUtils.commaSeparatedStringToAuthorityList("user,admin"));
        return user;
    }
}

// BrowserSecurityConfigure 配置PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

该类方法用于处理用户信息获取逻辑，允许任意用户名，以密码123456登录。



2.修改登录页

修改默认的表单登录页为自定义页面

2.1加入thymeleaf依赖

```
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
```

2.2新增login.html

```
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>登录页</title>
</head>
<body>
<div class="container">
    <form class="form-signin" method="post" action="/login">
        <h3 class="form-signin-heading">账户登录</h3>
        <p>
            <input type="text" id="username" name="username" class="form-control" placeholder="用户名" required autofocus>
        </p>
        <p>
            <input type="password" id="password" name="password" class="form-control" placeholder="密码" required>
        </p>
        <input name="_csrf" type="hidden" value="413eac03-3d27-4483-9469-330272833476"/>
        <button class="btn btn-lg btn-primary btn-block" type="submit">登录</button>
    </form>
</div>
</body>
<style>
    body {
        padding-top: 15px;
        padding-bottom: 15px;
        background-color: #eee;
    }
    .container {
        margin: 0 auto;
        width: 100%;
        padding-left: 15px;
        padding-right: 15px;
    }
    .form-signin {
        max-width: 330px;
        padding: 15px;
        margin: 0 auto;
        border: #eee3ee 1px solid;
        text-align: center;
        background-color: rgba(116, 193, 238,.3);
    }
    .form-signin-heading {
        color: #6f6f6f;
    }
    .form-control {
        padding: .5rem .75rem;
        font-size: 1rem;
        line-height: 1.25;
        color: #495057;
        background-color: #fff;
        background-image: none;
        background-clip: padding-box;
        border: 1px solid rgba(0,0,0,.15);
        border-radius: .25rem;
        transition: border-color ease-in-out .15s,box-shadow ease-in-out .15s;
    }
    .btn {
        padding: .5rem .75rem;
        font-size: 1rem;
        line-height: 1.25;
        color: #495057;
        background-image: none;
        background-clip: padding-box;
        border: 1px solid rgba(0,0,0,.15);
        border-radius: .25rem;
        width: 221px;
        background-color: #85ddf8;
    }
</style>
</html>
```

2.3新增LoginController，login请求返回login.html

```
package com.mbs.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/24 17:31
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
```

2.4 修改BrowserSecurityConfigure，添加登录页配置

```
package com.mbs.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/23 17:16
 */
@Configuration
public class BrowserSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                // 登录页
                .loginPage("/login")
                // 登录处理路径
                .loginProcessingUrl("/login")
                .and()
                // 授权配置
                .authorizeRequests()
                // 无需认证匹配
                .antMatchers("/login").permitAll()
                // 所有请求
                .anyRequest()
                // 都需要认证
                .authenticated()
                .and().csrf().disable();;

    }
}
```



3.未登录请求，根据请求路径后缀区分是返回JSON还是登录页

3.1新增BrowserSecurityController

```
package com.mbs.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class BrowserSecurityController {
    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @GetMapping("/authentication/require")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String requireAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            if (StringUtils.endsWithIgnoreCase(targetUrl, ".html"))
                redirectStrategy.sendRedirect(request, response, "/login");
        }
        return "访问的资源需要身份认证！";
    }
}
```

3.2修改BrowserSecurityConfigure，登录页和无需认证配置

```
package com.mbs.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/23 17:16
 */
@Configuration
public class BrowserSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                // 登录页
//                .loginPage("/login")
                .loginPage("/authentication/require")
                // 登录处理路径
                .loginProcessingUrl("/login")
                .and()
                // 授权配置
                .authorizeRequests()
                // 无需认证匹配
                .antMatchers("/login", "/authentication/require").permitAll()
                // 所有请求
                .anyRequest()
                // 都需要认证
                .authenticated();

    }
}

```



4.处理成功和失败逻辑

**修改默认的处理成功逻辑**

需要实现AuthenticationSuccessHandler接口

4.1新增MyAuthenticationSuccessHandler

```
package com.mbs.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(objectMapper.writeValueAsString(authentication));
    }
}
```

4.2修改BrowserSecurityConfigure

注入MyAuthenticationSuccessHandler，并指定config.successHandler

```
package com.mbs.security.config;

import com.mbs.security.handler.MyAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                // 登录页
//                .loginPage("/login")
                .loginPage("/authentication/require")
                // 登录处理路径
                .loginProcessingUrl("/login")
                // 登录成功处理逻辑
                .successHandler(myAuthenticationSuccessHandler)
                .and()
                // 授权配置
                .authorizeRequests()
                // 无需认证匹配
                .antMatchers("/login", "/authentication/require").permitAll()
                // 所有请求
                .anyRequest()
                // 都需要认证
                .authenticated()
                .and().csrf().disable();

    }
}
```

通过以上代码，登录页登录成功后将返回Authentication对象。

如果要想登录成功后跳转回原来路径，修改MyAuthenticationSuccessHandler

```
package com.mbs.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // 返回Authentication对象
//        response.setContentType("application/json;charset=utf-8");
//        response.getWriter().write(objectMapper.writeValueAsString(authentication));
        // 跳转回原路径
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        redirectStrategy.sendRedirect(request, response, savedRequest.getRedirectUrl());
    }
}
```

也可以指定登录后路径

redirectStrategy.sendRedirect(request, response, "/指定路径");

如果想在登录后获取Authentication对象

```
    @GetMapping("/getAuthentication")
    @ResponseBody
    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
    
    
    @GetMapping("/getAuthentication2")
    @ResponseBody
    public Authentication getAuthentication(Authentication authentication) {
        return authentication;
    }
```

**修改默认的处理失败逻辑**

4.3新增MyAuthenticationFailureHandler

```
package com.mbs.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private ObjectMapper mapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(mapper.writeValueAsString(exception.getMessage()));
    }
}
```

4.4修改BrowserSecurityConfigure

```
package com.mbs.security.config;

import com.mbs.security.handler.MyAuthenticationFailureHandler;
import com.mbs.security.handler.MyAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
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
                .antMatchers("/login", "/authentication/require").permitAll()
                // 所有请求
                .anyRequest()
                // 都需要认证
                .authenticated()
                .and().csrf().disable();

    }
}

```

