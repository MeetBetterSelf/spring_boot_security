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

### 添加验证码

1.新增依赖

```
		<dependency>
			<groupId>org.springframework.social</groupId>
			<artifactId>spring-social-config</artifactId>
			<version>1.1.6.RELEASE</version>
		</dependency>
```

2.新增ImageCode类

```
package com.mbs.security.utils;

import java.awt.image.BufferedImage;
import java.time.LocalDateTime;

public class ImageCode {

    private BufferedImage image;

    private String code;

    private LocalDateTime expireTime;

    public ImageCode(BufferedImage image, String code, int expireIn) {
        this.image = image;
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireIn);
    }

    public ImageCode(BufferedImage image, String code, LocalDateTime expireTime) {
        this.image = image;
        this.code = code;
        this.expireTime = expireTime;
    }

    public boolean isExpire() {
        return LocalDateTime.now().isAfter(expireTime);
    }

    public BufferedImage getImage() {
        return image;
    }

    public void setImage(BufferedImage image) {
        this.image = image;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public LocalDateTime getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(LocalDateTime expireTime) {
        this.expireTime = expireTime;
    }
}
```

3.新增验证码ValidateCodeController

```
package com.mbs.security.controller;

import com.mbs.security.utils.ImageCode;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Random;

@RestController
public class ValidateCodeController {

    public final static String SESSION_KEY_IMAGE_CODE = "SESSION_KEY_IMAGE_CODE";

    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @GetMapping("/code/image")
    public void createCode(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ImageCode imageCode = createImageCode();
        sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY_IMAGE_CODE, imageCode);
        ImageIO.write(imageCode.getImage(), "jpeg", response.getOutputStream());
    }

    private ImageCode createImageCode() {
        int width = 100; // 验证码图片宽度
        int height = 36; // 验证码图片长度
        int length = 4; // 验证码位数
        int expireIn = 60; // 验证码有效时间 60s

        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        Graphics g = image.getGraphics();

        Random random = new Random();

        g.setColor(getRandColor(200, 250));
        g.fillRect(0, 0, width, height);
        g.setFont(new Font("Times New Roman", Font.ITALIC, 20));
        g.setColor(getRandColor(160, 200));
        for (int i = 0; i < 155; i++) {
            int x = random.nextInt(width);
            int y = random.nextInt(height);
            int xl = random.nextInt(12);
            int yl = random.nextInt(12);
            g.drawLine(x, y, x + xl, y + yl);
        }

        StringBuilder sRand = new StringBuilder();
        for (int i = 0; i < length; i++) {
            String rand = String.valueOf(random.nextInt(10));
            sRand.append(rand);
            g.setColor(new Color(20 + random.nextInt(110), 20 + random.nextInt(110), 20 + random.nextInt(110)));
            g.drawString(rand, 13 * i + 6, 16);
        }

        g.dispose();

        return new ImageCode(image, sRand.toString(), expireIn);
    }

    private Color getRandColor(int fc, int bc) {
        Random random = new Random();
        if (fc > 255)
            fc = 255;

        if (bc > 255)
            bc = 255;
        int r = fc + random.nextInt(bc - fc);
        int g = fc + random.nextInt(bc - fc);
        int b = fc + random.nextInt(bc - fc);
        return new Color(r, g, b);
    }
}
```

4.修改BrowserSecurityConfigure

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
```

修改login.html页面

```
        <p>
            <input type="text" name="imageCode" placeholder="验证码"  class="form-control"  style="width: 90px;"/>
            <img src="/code/image"/>
        </p>
```

启动，访问：http://localhost:8080/hello

5.添加验证码校验

5.1新增验证码异常类

```
package com.mbs.security.exception;

import org.springframework.security.core.AuthenticationException;

public class ValidateCodeException extends AuthenticationException {
    private static final long serialVersionUID = 5022575393500654458L;

    public ValidateCodeException(String message) {
        super(message);
    }
}
```

5.2新增验证码过滤器

```
package com.mbs.security.filter;

import com.mbs.security.controller.ValidateCodeController;
import com.mbs.security.exception.ValidateCodeException;
import com.mbs.security.utils.ImageCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class ValidateCodeFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        if (StringUtils.equalsIgnoreCase("/login", httpServletRequest.getRequestURI())
                && StringUtils.equalsIgnoreCase(httpServletRequest.getMethod(), "post")) {
            try {
                validateCode(new ServletWebRequest(httpServletRequest));
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
                return;
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void validateCode(ServletWebRequest servletWebRequest) throws ServletRequestBindingException {
        ImageCode codeInSession = (ImageCode) sessionStrategy.getAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY_IMAGE_CODE);
        String codeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "imageCode");

        if (StringUtils.isEmpty(codeInRequest)) {
            throw new ValidateCodeException("验证码不能为空！");
        }
        if (codeInSession == null) {
            throw new ValidateCodeException("验证码不存在！");
        }
        if (codeInSession.isExpire()) {
            sessionStrategy.removeAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY_IMAGE_CODE);
            throw new ValidateCodeException("验证码已过期！");
        }
        if (!StringUtils.equalsIgnoreCase(codeInSession.getCode(), codeInRequest)) {
            throw new ValidateCodeException("验证码不正确！");
        }
        sessionStrategy.removeAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY_IMAGE_CODE);

    }

}
```

5.3配置验证码过滤器

```
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
```

启动，访问http://localhost:8080/hello，输入错误的验证，可看到相关提示。

此异常处理较为简陋

# Spring Security Oauth2

Oauth2.0是一种用来规范令牌（Token）发放的授权机制。

主要包含四种授权模式：授权码模式、密码模式、客户端模式和简化模式。



授权码模式流程：

A. 客户端将用户导向认证服务器；

B. 用户决定是否给客户端授权；

C. 同意授权后，认证服务器将用户导向客户端提供的URL，并附上授权码；

D. 客户端通过重定向URL和授权码到认证服务器换取令牌；

E. 校验无误后发放令牌。



密码模式流程：

A. 用户向客户端提供用户名和密码；

B. 客户端向认证服务器换取令牌；

C. 发放令牌。



Spring Security OAuth2是对Oauth2协议进行了实现，主要包含认证服务器和资源服务器这两大块的实现。

认证服务器主要包含了四种授权模式的实现和Token的生成与存储，我们也可以在认证服务器中自定义获取Token的方式；资源服务器主要是在Spring Security的过滤器链上加了OAuth2AuthenticationProcessingFilter过滤器，即使用OAuth2协议发放令牌认证的方式来保护我们的资源。



## 配置认证服务器

1.新增依赖

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.3.2.RELEASE</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.mbs</groupId>
	<artifactId>spring-boot-security-oauth2-guide</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>spring-boot-security-oauth2-guide</name>
	<description>Demo project for Spring Boot And Spring Security</description>

	<properties>
		<java.version>1.8</java.version>
	</properties>

	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.social</groupId>
			<artifactId>spring-social-config</artifactId>
			<version>1.1.6.RELEASE</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-oauth2</artifactId>
			<version>2.2.4.RELEASE</version>
		</dependency>
		<dependency>
			<groupId>org.apache.commons</groupId>
			<artifactId>commons-lang3</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
			<exclusions>
				<exclusion>
					<groupId>org.junit.vintage</groupId>
					<artifactId>junit-vintage-engine</artifactId>
				</exclusion>
			</exclusions>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>
</project>
```

2.新增一个UserDetails接口实现类OpenUserDetails

```
package com.mbs.security.model.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/26 15:35
 */
public class OpenUserDetails implements UserDetails {
    private static final long serialVersionUID = -6806746213364059582L;

    private String username;
    private String password;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked= true;
    private boolean credentialsNonExpired= true;
    private boolean enabled= true;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities == null) {
            return Collections.EMPTY_LIST;
        }
        return authorities;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }
}

```

3.新增一个UserDetailsService接口实现类UserDetailsServiceImpl

```
package com.mbs.security.service;

import com.mbs.security.model.entity.OpenUserDetails;
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
        // spring security oauth2
        OpenUserDetails userDetails = new OpenUserDetails();
        userDetails.setUsername(username);
        userDetails.setPassword(passwordEncoder.encode("123456"));
        userDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("user"));
        
        return userDetails;
    }
}

```

4.新增一个AuthorizationServerConfiguration认证类，

```
package com.mbs.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/26 15:54
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
```

5.添加配置application.properties

```
security.oauth2.client.client-id=test
security.oauth2.client.client-secret=123456
```

启动项目，控制台打印

security.oauth2.client.client-id = test
security.oauth2.client.client-secret = ****

## 授权码模式获取token

浏览器访问：http://localhost:8080/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://aaa.com&scope=all&state=hello

URL中的几个参数中response_type必须为code，表示授权码模式；client_id是配置文件中指定的test；redirect_uri为回调地址，主要是用来重定向获取授权码的；scope指定为all，表示所有权限。

访问之后出现登录界面，输入任意用户名，密码为123456，登录

> 提示：error="invalid_request", error_description="At least one redirect_uri must be registered with the client."

配置文件添加配置

```
security.oauth2.client.registered-redirect-uri=http://aaa.com
```

重新访问并登录，可以看到出现授权页，选择Approve并点击Authorize

随后会跳转到路径：http://aaa.com/?code=MLhO9H&state=hello

此时可以获取到相应的授权码了 ，用这个授权码从认证服务器获取令牌

使用postman发起一个post请求：

localhost:8080/oauth/token?grant_type=authorization_code&code=KKJZh5&redirect_uri=http://aaa.com&scope=all&client_id=test

> grant_type固定为authorization_code
>
> code为获取的授权码
>
> redirect_uri必须与之前一致
>
> scope权限范围，all所有权限
>
> client_id客户端ID

headers添加Authorization Basic dGVzdDoxMjM0NTY=

dGVzdDoxMjM0NTY= 为clientId:clientSecret（test:123456） 进行base64加密值

可以看到返回token：

```
{

  "access_token": "39a7e1ab-cfd7-494d-a2ca-1b6c244e6970",

  "token_type": "bearer",

  "refresh_token": "d94b3c3a-3cef-4577-8a20-782e86590456",

  "expires_in": 43199,

  "scope": "all"

}
```

一个code只能获取一次token，多次点击将出现Invalid authorization code: KKJZh5

## 密码模式获取token

密码模式请求路径

localhost:8080/oauth/token?grant_type=password&scope=all&username=hello&password=123456

> grant_type固定为password
>
> username用户名
>
> password密码
>
> scope权限范围，all所有权限

同样需要添加headers，Authorization Basic dGVzdDoxMjM0NTY=

```
{
    "access_token": "9e7a0117-e104-4d03-aed1-4ada6033cf53",
    "token_type": "bearer",
    "refresh_token": "8216c5fd-5301-499d-9336-d189c0f6cac9",
    "expires_in": 43199,
    "scope": "all"
}
```



## 配置资源服务器

此时通过获取的token 去访问localhost:8080/hello，headers添加Authorization 值Bearer 9e7a0117-e104-4d03-aed1-4ada6033cf53，会出现401。

配置资源服务类

```
package com.mbs.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/26 17:09
 */
@Order(2)
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration {
}

```

修改认证服务类

```
package com.mbs.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/26 15:54
 */
@Order(1)
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

```

新增一个TestController

```
package com.mbs.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("hello")
    public String hello() {
        return "hello spring security";
    }
}
```

重复上面授权流程。

PS：@Order加在认证与资源服务类之后，授权码模式认证能成功，但是访问资源时会出现401错误。这里主要时由于资源服务类与spring security的websecurityconfigurerAdapter的相互影响。

WebSecurityConfigurerAdapter与ResourceServerConfigurerAdapter的区别联系可参考链接文章：

https://www.jianshu.com/p/fe1194ca8ecd

两者其实都是对资源权限的控制，一个是spring security一个是spring security oauth2，ResourceServerConfigurer的优先级更高

## 自定义Token

本文将通过自定义用户名密码获取令牌，会沿用上节代码。

spring security oauth2自带的获取令牌流程：

1.由request获取对应的客户端ID(ClientId)

2.通过ClientDetailService的loadClientByClientId方法获取ClientDetails

3.TokenRequest构造器生成 TokenRequest

4.通过 TokenRequest的 createOAuth2Request方法获取 OAuth2Request

5.通过 Authentication和 OAuth2Request构造出 OAuth2Authentication

6.通过 AuthorizationServerTokenServices 生成 OAuth2AccessToken

7.返回 OAuth2AccessToken



1.授权服务类

```
package com.mbs.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/26 15:54
 */
//@Order(1)
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
```

2.资源服务类，添加登录处理路径以及登录成功、失败处理了逻辑

```
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

```

3.创建MyAuthenticationFailureHandler和MyAuthenticationSuccessHandler

MyAuthenticationFailureHandler类直接返回错误信息

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

MyAuthenticationSuccessHandler，自定义生成令牌

```
package com.mbs.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;

@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // 1. 从请求头中获取 ClientId
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Basic ")) {
            throw new UnapprovedClientAuthenticationException("请求头中无client信息");
        }

        String[] tokens = this.extractAndDecodeHeader(header, request);
        String clientId = tokens[0];
        String clientSecret = tokens[1];

        TokenRequest tokenRequest = null;

        // 2. 通过 ClientDetailsService 获取 ClientDetails
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        // 3. 校验 ClientId和 ClientSecret的正确性
        if (clientDetails == null) {
            throw new UnapprovedClientAuthenticationException("clientId:" + clientId + "对应的信息不存在");
        } else if (!StringUtils.equals(clientDetails.getClientSecret(), clientSecret)) {
            throw new UnapprovedClientAuthenticationException("clientSecret不正确");
        } else {
            // 4. 通过 TokenRequest构造器生成 TokenRequest
            tokenRequest = new TokenRequest(new HashMap<>(), clientId, clientDetails.getScope(), "custom");
        }

        // 5. 通过 TokenRequest的 createOAuth2Request方法获取 OAuth2Request
        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
        // 6. 通过 Authentication和 OAuth2Request构造出 OAuth2Authentication
        OAuth2Authentication auth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);

        // 7. 通过 AuthorizationServerTokenServices 生成 OAuth2AccessToken
        OAuth2AccessToken token = authorizationServerTokenServices.createAccessToken(auth2Authentication);

        // 8. 返回 Token
        log.info("登录成功");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(token));
    }

    private String[] extractAndDecodeHeader(String header, HttpServletRequest request) {
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Token);
        } catch (IllegalArgumentException var7) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }

        String token = new String(decoded, StandardCharsets.UTF_8);
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        } else {
            return new String[]{token.substring(0, delim), token.substring(delim + 1)};
        }
    }
}
```

启动项目，访问localhost:8080/login?username=hello&password=12345612，请求头headers添加Authorization Basic dGVzdDoxMjM0NTY=

可以成功获取到令牌，根据令牌调用接口即可获取数据。

## 自定义令牌配置

Spring Security允许我们自定义令牌配置，如令牌有效期、存储策略等，也可使用JWT来替换默认令牌。

1.自定义令牌需要在认证服务类继承AuthorizationServerConfigurerAdapter，并重写它的configure(ClientDetailsServiceConfigurer clients)方法：

```

```

