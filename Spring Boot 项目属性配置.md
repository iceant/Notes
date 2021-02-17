# 参考网站

- [Spring Security 5.4.2](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5)
- [Spring Security RunAsAuth](https://www.baeldung.com/spring-security-run-as-auth)

# Spring Boot 项目属性配置

```xml
<properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
    <encoding>UTF-8</encoding>
    <java.version>1.8</java.version>
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
</properties>
```



# 加入阿里云 maven 库

```xml
<repositories>
    <repository>
        <id>aliyun</id>
        <url>https://maven.aliyun.com/repository/public</url>
        <releases>
            <enabled>true</enabled>
        </releases>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>
```

# Spring milestone 库

```xml
<repositories>
	<repository>
    	<id>org.springframework.maven.milestone</id>
        <name>Spring Maven Milestone Repository</name>
        <url>http://repo.spring.io/milestone</url>
    </repository>
</repositories>
```



# i18n 配置

application.properties 中配置

```properties
################################################################################
## i18n
spring.messages.basename=static/i18n/messages
```

```text
/src
	|- resources/
		|- static/
			|- i18n/
				|- messages.properties
				|- messages_en.properties
				|- messages_zh_CN.properties
```

messages.properties 不能少



# 配置数据库

## SQLite

```properties
################################################################################
## jdbc
spring.datasource.driver-class-name=org.sqlite.JDBC
spring.datasource.url=classpath:/static/resources/app.db
```

# Jackson 不输出空值

```properties
spring.jackson.default-property-inclusion=non_empty
```

# Jackson 将 long 转换为字符串，避免精度损失

```properties
spring.jackson.generator.write-numbers-as-strings=true
```

# 认证过程

![abstractauthenticationprocessingfilter](D:\Projects\Notes\assets\abstractauthenticationprocessingfilter.png)

## DaoAuthenticationProvider

![daoauthenticationprovider](D:\Projects\Notes\assets\daoauthenticationprovider.png)

![number 1](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/images/icons/number_1.png) The authentication `Filter` from [Reading the Username & Password](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#servlet-authentication-unpwd-input) passes a `UsernamePasswordAuthenticationToken` to the `AuthenticationManager` which is implemented by [`ProviderManager`](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#servlet-authentication-providermanager).

![number 2](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/images/icons/number_2.png) The `ProviderManager` is configured to use an [AuthenticationProvider](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#servlet-authentication-authenticationprovider) of type `DaoAuthenticationProvider`.

![number 3](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/images/icons/number_3.png) `DaoAuthenticationProvider` looks up the `UserDetails` from the `UserDetailsService`.

![number 4](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/images/icons/number_4.png) `DaoAuthenticationProvider` then uses the [`PasswordEncoder`](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#servlet-authentication-password-storage) to validate the password on the `UserDetails` returned in the previous step.

![number 5](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/images/icons/number_5.png) When authentication is successful, the [`Authentication`](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#servlet-authentication-authentication) that is returned is of type `UsernamePasswordAuthenticationToken` and has a principal that is the `UserDetails` returned by the configured `UserDetailsService`. Ultimately, the returned `UsernamePasswordAuthenticationToken` will be set on the [`SecurityContextHolder`](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#servlet-authentication-securitycontextholder) by the authentication `Filter`.

# 自定义登录界面

## WebSecurityConfig.java

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().cors()
                .and()
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated()
        .and()
            .formLogin()
                .loginPage("/pages/login.html").permitAll()
                ;
    }
}
```

## login.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<form action="/login" method="post">
    <input type="text" name="username" placeholder="username">
    <input type="password" name="password" placeholder="password">
    <input type="submit" value="Login">
</form>
</body>
</html>
```

# 自定义登录成功和识别的处理逻辑

## 登录成功

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {
    private static Logger  logger = LoggerFactory.getLogger(AuthenticationSuccessHandlerImpl.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        logger.info("onAuthenticationSuccess-1:");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        logger.info("onAuthenticationSuccess-2:");
        logger.info("Authentication:{}", authentication);
        httpServletResponse.sendRedirect("/api/hello");
    }
}
```



## 登录失败

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {
    private static Logger logger = LoggerFactory.getLogger(AuthenticationFailureHandlerImpl.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        logger.info("onAuthenticationFailure");
    }
}
```

# JdbcUserDetailsManager 使用

## JdbcUserDetailsManager 使用的数据库

```sql
create table if not exists users(
    id integer primary key autoincrement ,
    username varchar(50) not null unique ,
    password varchar(500) not null ,
    enabled boolean not null default true );

create table if not exists authorities(
    id integer primary key autoincrement ,
    username varchar(50) not null,
    authority varchar(50) not null );

create table if not exists groups(
    id integer primary key autoincrement ,
    group_name varchar(50) not null
);

create table if not exists group_members(
    group_id integer not null ,
    username varchar(50) not null
);

create table if not exists group_authorities(
    group_id integer not null ,
    authority varchar(50) not null
);
```

## JdbcUserDetailsManager配置

```java
@Bean
public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
}

@Bean
public UserDetailsService userDetailsService(){
    //        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    //        manager.createUser(User.withUsername("user").password("password").roles("USER").build());
    //        manager.createUser(User.withUsername("admin").password("password").roles("ADMIN").build());
    //        return manager;

    PasswordEncoder passwordEncoder = passwordEncoder();
    String password = passwordEncoder.encode("password");

    JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();
    userDetailsManager.setEnableAuthorities(true);
    userDetailsManager.setEnableGroups(true);
    userDetailsManager.setDataSource(dataSource);
    if(!userDetailsManager.userExists("user")){
        userDetailsManager.createUser(User.withUsername("user").password(password)
                                      .roles("USER").build());
    }
    if(!userDetailsManager.userExists("admin")){
        userDetailsManager.createUser(User.withUsername("admin").password(password)
                                      .roles("USER", "ADMIN").build());
    }
    return userDetailsManager;
}
```

# RunAs配置

## 多AuthenticationProvider配置

- 明确指定 `daoAuthenticationProvider`，**不指定无法正常登录**

```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(daoAuthenticationProvider());
}

@Bean
public AuthenticationProvider daoAuthenticationProvider(){
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder());
    provider.setUserDetailsService(userDetailsService());
    return provider;
}

@Bean
public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
}

@Bean
public UserDetailsService userDetailsService(){
    //        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    //        manager.createUser(User.withUsername("user").password("password").roles("USER").build());
    //        manager.createUser(User.withUsername("admin").password("password").roles("ADMIN").build());
    //        return manager;

    PasswordEncoder passwordEncoder = passwordEncoder();
    String password = passwordEncoder.encode("password");

    JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();
    userDetailsManager.setEnableAuthorities(true);
    userDetailsManager.setEnableGroups(true);
    userDetailsManager.setDataSource(dataSource);
    if(!userDetailsManager.userExists("user")){
        userDetailsManager.createUser(User.withUsername("user").password(password).roles("USER").build());
    }
    if(!userDetailsManager.userExists("admin")){
        userDetailsManager.createUser(User.withUsername("admin").password(password).roles("USER", "ADMIN").build());
    }
    return userDetailsManager;
}

```

## RunAsConfig(MethodSecurityConfiguration) 配置

- AuthenticationProvider 和 RunAsManager 的 **key 一定要一致**

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.intercept.RunAsImplAuthenticationProvider;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.RunAsManagerImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class RunAsConfig extends GlobalMethodSecurityConfiguration {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(runAsAuthenticationProvider());
    }

    @Bean
    public AuthenticationProvider runAsAuthenticationProvider() {
        RunAsImplAuthenticationProvider authProvider = new RunAsImplAuthenticationProvider();
        authProvider.setKey("MyRunAsKey");
        return authProvider;
    }

    @Override
    protected RunAsManager runAsManager() {
        RunAsManagerImpl runAsManager = new RunAsManagerImpl();
        runAsManager.setKey("MyRunAsKey");
        return runAsManager;
    }
}
```

## Controller

`@Secured` 指定以什么身份运行方法

```java
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/runas")
public class RunAsController {

    @Secured({ "ROLE_USER", "RUN_AS_REPORTER" })
    @RequestMapping
    @ResponseBody
    public String tryRunAs() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Current User Authorities inside this RunAS method only "
                + auth.getAuthorities().toString();
    }

}
```



# Captcha 认证码通过Filter实现

![image-20210209232454762](D:\Projects\Notes\assets\captcha.png)

## 依赖

```xml
<dependency>
    <groupId>com.github.penggle</groupId>
    <artifactId>kaptcha</artifactId>
    <version>2.3.2</version>
</dependency>
```

## VerificationCodeFilter

```java
import com.github.iceant.spring.demo.errors.VerificationCodeException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


public class VerificationCodeFilter extends OncePerRequestFilter {

    private AuthenticationFailureHandler authenticationFailureHandler;

    public AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return authenticationFailureHandler;
    }

    public VerificationCodeFilter setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
        return this;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        if(!"/login".equalsIgnoreCase(httpServletRequest.getRequestURI())){
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }else{
            try {
                verificationCode(httpServletRequest);
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }catch (VerificationCodeException e){
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest,
                        httpServletResponse, e);
            }
        }
    }

    private void verificationCode(HttpServletRequest httpServletRequest) throws VerificationCodeException{
       String requestCode = httpServletRequest.getParameter("captcha");
        HttpSession session = httpServletRequest.getSession();
        String savedCode = (String) session.getAttribute("captcha");
        if(savedCode!=null && savedCode.length()>0){
            session.removeAttribute("captcha");
        }
        if(requestCode==null || requestCode.length()<1
                || savedCode==null || savedCode.length()<1
                || !requestCode.equals(savedCode)){
            throw new VerificationCodeException();
        }
    }
}
```

## VerificationCodeException

```java
import org.springframework.security.core.AuthenticationException;

public class VerificationCodeException extends AuthenticationException {
    public VerificationCodeException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public VerificationCodeException(String msg) {
        super(msg);
    }

    public VerificationCodeException() {
       super("Invalid Captcha");
    }
}

```

## 添加到 Filter Chain 中

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	// ...
    http.addFilterBefore(new VerificationCodeFilter()
                         .setAuthenticationFailureHandler(authenticationFailureHandler()),
                         UsernamePasswordAuthenticationFilter.class);
}
```

## 页面HTML

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<form action="/login" method="post">
    <input type="text" name="username" placeholder="username">
    <input type="password" name="password" placeholder="password">
    <div style="display: flex;">
        <input type="text" name="captcha" placeholder="captcha">
        <img src="/captcha.png" alt="captcha" height="50px" width="150px" style="margin-left: 20px">
    </div>
    <input type="submit" value="Login">
</form>
</body>
</html>
```

# Captcha 认证通过 AuthenticationProvider实现

## WebSecurityConfig 中装配

- AuthenticationProvider 负责完成认证，对验证码的结果进行判断，如果不正确，返回错误，否则正常处理
- AuthenticationDetailsSource 产生 AuthenticationDetails，提供认证的额外详细信息，比如用户的ip地址等
- AuthenticationDetails， 额外的认证信息，验证码例子中包含验证码是否正确的信息

```java

@Autowired
CaptchaAuthenticationProvider captchaAuthenticationProvider;

@Autowired
WebAuthenticationDetailsSourceImpl webAuthenticationDetailsSource;

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable().cors()
        .and()
        .authorizeRequests()
        .antMatchers("/admin/api/**").hasRole("ADMIN")
        .antMatchers("/user/api/**").hasRole("USER")
        .antMatchers("/app/api/**").permitAll()
        .antMatchers("/login", "/captcha.png").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .authenticationDetailsSource(webAuthenticationDetailsSource)
        .loginPage("/pages/login.html").permitAll()
        .loginProcessingUrl("/login")
        //                .successHandler(authenticationSuccessHandler())
        .failureHandler(authenticationFailureHandler())
        ;

    //        http.addFilterBefore(new VerificationCodeFilter()
    //                .setAuthenticationFailureHandler(authenticationFailureHandler()),
    //                UsernamePasswordAuthenticationFilter.class);
}


@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //        auth.authenticationProvider(jdbcAuthenticationProvider());
    auth.authenticationProvider(captchaAuthenticationProvider);
}

```



## AuthenticationProvider

通过UsernamePasswordAuthenticationToken.getDetails()来获得额外的认证信息，这个信息是通过 AuthenticationDetailsSource 注入的

```java
import com.github.iceant.spring.demo.errors.VerificationCodeException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CaptchaAuthenticationProvider extends DaoAuthenticationProvider {
    public CaptchaAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(passwordEncoder);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        WebAuthenticationDetailsImpl details = (WebAuthenticationDetailsImpl) authentication.getDetails();
        if(!details.getImageCodeIsRight()){
            throw new VerificationCodeException();
        }
        super.additionalAuthenticationChecks(userDetails, authentication);
    }
}
```

## AuthenticationDetails

完成额外的认证信息

```java
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class WebAuthenticationDetailsImpl extends WebAuthenticationDetails {
    private Boolean imageCodeIsRight;

    public Boolean getImageCodeIsRight() {
        return imageCodeIsRight;
    }

    public WebAuthenticationDetailsImpl setImageCodeIsRight(Boolean imageCodeIsRight) {
        this.imageCodeIsRight = imageCodeIsRight;
        return this;
    }

    public WebAuthenticationDetailsImpl(HttpServletRequest request) {
        super(request);
        HttpSession session = request.getSession();
        String requestCode = request.getParameter("captcha");

        String savedCode = (String) session.getAttribute("captcha");
        if(savedCode!=null && savedCode.length()>0){
            session.removeAttribute("captcha");
            if(savedCode.equals(requestCode)){
                this.imageCodeIsRight = true;
            }else{
                this.imageCodeIsRight = false;
            }
        }
    }
}

```

## AuthenticationDetailsSource 

```java
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class WebAuthenticationDetailsSourceImpl implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new WebAuthenticationDetailsImpl(context);
    }
}

```

# 自动登录

## 散列方案

WebSecurityConfig 中添加

- key 可以防止用户访问系统的另一个实例时自动登录策略失效的问题

```java
 http.rememberMe()
     .userDetailsService(userDetailsService())
     .key("demo-remember-me-key")
     ;
```

## 持久方案

```sql
create table if not exists persistent_logins(
    username varchar(50) not null,
    series varchar(64) primary key ,
    token varchar(64) not null ,
    last_used timestamp not null
);
```

```java
@Bean
public PersistentTokenRepository persistentTokenRepository(){
    JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
    tokenRepository.setDataSource(dataSource);
    return tokenRepository;
}

```

```java
http.rememberMe()
    .userDetailsService(userDetailsService())
    .tokenRepository(persistentTokenRepository())
    ;

```

# Session 过期

最少1分钟

```properties
server.session.timeout=60
```

可以通过自定义 InvalidSessionStrategy 来实现满足个性化需求的过期策略

```java
http.sessionManagement().invalidSessionStrategy(new MyInvalidSessionStrategy());
```

# Session 并发控制

只允许一个 session

```java
 http.sessionManagement()
                .maximumSessions(1);
```

当用户多地登录时，之前登录的session会被踢出，会出现以下错误

```text
This session has been expired (possibly due to multiple concurrent logins being attempted as the same user).
```

ConcurrentSessionControlAuthenticationStrategy 负责控制



如果想实现已经有登录的情况下，不允许登录，可以这样配置：

```java
http.sessionManagement()
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true)
    ;
```

## UserDetail确保实现了 equals 和 hashCode

如果不实现，session 并发控制无法实现

# Redis 整合

TBD

# CORS 跨域支持

在 WebSecurityConfig 中启用 cors

``` java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.cors();
}
```

添加 CorsConfig

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

# OAuth 2.0 

## 运行流程

1. Resource Owner: 资源所有者，通常指用户
2. Resource Server: 资源服务器，存放受保护资源的服务器
3. Access Token：访问令牌，访问资源需要使用访问令牌
4. Client: 请求访问资源的第三方
5. Authorization Server: 授权服务器，发放令牌

![image-20210210075919305](D:\Projects\Notes\assets\OAuth)

(A) 客户端向资源所有者请求资源访问许可

(B)资源所有者同意客户访问 

(C)客户端向授权服务器申请访问令牌

(D)授权服务器验证后发放访问令牌

(E)客户端使用令牌访问资源

(F)资源服务器确认令牌有效后向客户端发放资源

## 授权码模式（Authorization Code）

授权码模式完整运行流程

![image-20210210081106042](D:\Projects\Notes\assets\authorization_code_mode)

将访问请求导向授权服务器，授权服务器给客户端发放令牌

```text
https://graph.qq.com/oauth2.0/show?which=Login&display=pc&response_type=code&client_id=100222333&redirect_uri=https://passport.csdn.net/account/login?oath_provider=QQProvider&state=test
```

这里CSDN就是客户端

## 隐式授权模式(Implicit)

客户端一般是指用户浏览器。访问令牌通过重定向的方式传递到用户浏览器中，再通过浏览器的Javascript代码来获取访问令牌。

由于访问令牌直接暴露在浏览器端，所以隐私授权模式可能会导致访问令牌被黑客获取，仅适用于临时访问的场景。QQ针对移动端用户采用的是隐式授权模式

![image-20210210081757834](D:\Projects\Notes\assets\oauth_implicit_mode)



## 密码授权模式(Password Credentials)

客户端直接携带用户密码向授权服务器申请令牌

![image-20210210082145198](D:\Projects\Notes\assets\oauth_password_credentials_mode)

## 客户端授权模式(Client Credentials)

![image-20210210082249860](D:\Projects\Notes\assets\oauth_client_credentials_mode)



## Spring Boot 2.0 ClientRegistration 配置表

`CommonOAuth2Provider`中包含对 google, facebook, github, okta 的支持

| Spring Boot 2.x                                              | ClientRegistration                                       |
| :----------------------------------------------------------- | :------------------------------------------------------- |
| `spring.security.oauth2.client.registration.*[registrationId]*` | `registrationId`                                         |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-id` | `clientId`                                               |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-secret` | `clientSecret`                                           |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-authentication-method` | `clientAuthenticationMethod`                             |
| `spring.security.oauth2.client.registration.*[registrationId]*.authorization-grant-type` | `authorizationGrantType`                                 |
| `spring.security.oauth2.client.registration.*[registrationId]*.redirect-uri` | `redirectUri`                                            |
| `spring.security.oauth2.client.registration.*[registrationId]*.scope` | `scopes`                                                 |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-name` | `clientName`                                             |
| `spring.security.oauth2.client.provider.*[providerId]*.authorization-uri` | `providerDetails.authorizationUri`                       |
| `spring.security.oauth2.client.provider.*[providerId]*.token-uri` | `providerDetails.tokenUri`                               |
| `spring.security.oauth2.client.provider.*[providerId]*.jwk-set-uri` | `providerDetails.jwkSetUri`                              |
| `spring.security.oauth2.client.provider.*[providerId]*.issuer-uri` | `providerDetails.issuerUri`                              |
| `spring.security.oauth2.client.provider.*[providerId]*.user-info-uri` | `providerDetails.userInfoEndpoint.uri`                   |
| `spring.security.oauth2.client.provider.*[providerId]*.user-info-authentication-method` | `providerDetails.userInfoEndpoint.authenticationMethod`  |
| `spring.security.oauth2.client.provider.*[providerId]*.user-name-attribute` | `providerDetails.userInfoEndpoint.userNameAttributeName` |

## OAuth2LoginAuthenticationProvider

负责认证

```java
@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OAuth2LoginAuthenticationToken loginAuthenticationToken = (OAuth2LoginAuthenticationToken) authentication;
    // Section 3.1.2.1 Authentication Request -
    // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest scope
    // REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
    if (loginAuthenticationToken.getAuthorizationExchange().getAuthorizationRequest().getScopes()
        .contains("openid")) {
        // This is an OpenID Connect Authentication Request so return null
        // and let OidcAuthorizationCodeAuthenticationProvider handle it instead
        return null;
    }
    OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken;
    try {
        authorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken) this.authorizationCodeAuthenticationProvider
            .authenticate(new OAuth2AuthorizationCodeAuthenticationToken(
                loginAuthenticationToken.getClientRegistration(),
                loginAuthenticationToken.getAuthorizationExchange()));
    }
    catch (OAuth2AuthorizationException ex) {
        OAuth2Error oauth2Error = ex.getError();
        throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    OAuth2AccessToken accessToken = authorizationCodeAuthenticationToken.getAccessToken();
    Map<String, Object> additionalParameters = authorizationCodeAuthenticationToken.getAdditionalParameters();
    OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(
        loginAuthenticationToken.getClientRegistration(), accessToken, additionalParameters));
    Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper
        .mapAuthorities(oauth2User.getAuthorities());
    OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
        loginAuthenticationToken.getClientRegistration(), loginAuthenticationToken.getAuthorizationExchange(),
        oauth2User, mappedAuthorities, accessToken, authorizationCodeAuthenticationToken.getRefreshToken());
    authenticationResult.setDetails(loginAuthenticationToken.getDetails());
    return authenticationResult;
}
```



## OAuth 2.0 Client 配置

- 组装顺序ClientRegistration→ClientRegistrationRepository→OAuth2AuthorizedClientService→OAuth2AuthorizedClientRepository
- 请求端口：
  - authorizationEndpoint 对应配置中 spring.security.oauth2.client.provider.<id>.authorization-uri
  - redirectionEndpoint 对应配置中 spring.security.oauth2.client.registration.<id>.redirect-uri
  - tokenEndpoint 对应配置中 spring.security.oauth2.client.provider.<id>.token-uri
  - userInfoEndpoint 对应配置中 spring.security.oauth2.client.provider.<id>.user-info-uri
- tokenEndpoint.accessTokenResponseClient: 负责发起请求，并解析返回数据，转换为 OAuth2AccessTokenResponse
- userInfoEndpoint.userService 负责处理 OAuth2UserRequest 向服务器发起请求，并解析返回的结果，返回OAuth2User

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(this.clientRegistrationRepository())
                .authorizedClientRepository(this.authorizedClientRepository())
                .authorizedClientService(this.authorizedClientService())
                .loginPage("/login")
                .authorizationEndpoint(authorization -> authorization
                    .baseUri(this.authorizationRequestBaseUri())
                    .authorizationRequestRepository(this.authorizationRequestRepository())
                    .authorizationRequestResolver(this.authorizationRequestResolver())
                )
                .redirectionEndpoint(redirection -> redirection
                    .baseUri(this.authorizationResponseBaseUri())
                )
                .tokenEndpoint(token -> token
                    .accessTokenResponseClient(this.accessTokenResponseClient())
                )
                .userInfoEndpoint(userInfo -> userInfo
                    .userAuthoritiesMapper(this.userAuthoritiesMapper())
                    .userService(this.oauth2UserService())
                    .oidcUserService(this.oidcUserService())
                )
            );
    }
}
```

## GitHub 例子解析

- 用户点击登录，访问 `http://localhost:8080/oauth2/authorization/github`地址请求认证，返回代码302，进行重定向
- 重定向的地址为:`https://github.com/login/oauth/authorize?response_type=code&client_id=563cxxxxxxxxxx8340&scope=read:user&state=2Hwnsfsafvsxdfwqerwvasfsafsdfsadfwervcsdsdfsdds9ho%3D&redirect_uri=http://localhost:8080/login/oauth2/code/github`
- 被authorize服务器重定向回 `http://localhost:8080/login/oauth2/code/github?code=6b4xxxxxxxxxxxee6d&state=2Hwnqp19sMi5Vnwyq_ETycRgrF-O0uk3a1xTIcKK9ho=`
- localhost 接收到返回，重定向到之前访问的网站

# 配置 OAuth2Server

## pom.xml

```xml
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
        <groupId>org.springframework.security.oauth.boot</groupId>
        <artifactId>spring-security-oauth2-autoconfigure</artifactId>
        <version>2.4.2</version>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```



## AuthorizationServerConfig

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Profile("simple")
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    final PasswordEncoder passwordEncoder;

    public AuthorizationServerConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        super.configure(security);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        super.configure(clients);
        clients.inMemory().withClient("client-for-server")
                .secret(passwordEncoder.encode("client-for-server"))
                .authorizedGrantTypes("authorization_code", "implicit")
                .accessTokenValiditySeconds(7200)
                .refreshTokenValiditySeconds(72000)
                .redirectUris("http://oauth2client:8080/login/oauth2/code/authorizationserver")
                .additionalInformation()
                .resourceIds(ResourceServerConfig.RESOURCE_ID)
                .authorities("ROLE_CLIENT")
                .scopes("profile", "email", "phone", "any")
                .autoApprove("profile")
        ;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
    }
}

```

## ResourceServerConfig

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

@Profile("simple")
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(ResourceServerConfig.class);

    public static final String RESOURCE_ID="authorizationserver";

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        super.configure(resources);
        resources.resourceId(RESOURCE_ID);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        log.info("ResourceServerConfig::configure(http)");
        http.requestMatchers().antMatchers("/me")
                .and()
                .authorizeRequests().anyRequest().authenticated();
    }
}

```

## WebSecurityConfig

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Profile("simple")
@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("password")).roles("USER")
                .and()
                .withUser("admin").password(passwordEncoder().encode("password")).roles("ADMIN")
        ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("SecurityConfig::config(http)");
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().hasAnyRole("USER", "ADMIN")
                .and().formLogin();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().mvcMatchers("/favicon.ico");
    }

}

```

## SpringApplication

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Profile;

@Profile("simple")
@SpringBootApplication
public class SimpleAuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(SimpleAuthorizationServerApplication.class, args);
    }
}

```

# 配置 OAuth2Client

## pom.xml

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
    </dependency>
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
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```



## WebSecurityConfig

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
                .antMatchers("/login/oauth2/**", "/oauth2/**", "/error", "/login", "/logout").permitAll()
                .anyRequest().authenticated()
            .and().oauth2Login()
            .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    .maximumSessions(1);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().mvcMatchers("/favicon.ico");
    }
}

```

## application.yml

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          authorizationserver:
            client-id: client-for-server
            client-secret: client-for-server
            provider: authorizationserver
            authorization-grant-type: authorization_code
            client-authentication-method: basic
            scope: profile,email,phone
            redirect-uri-template: "{baseUrl}/login/oauth2/code/{registrationId}"
            redirect-uri: "{baseUrl}/{action}/oauth2/code/{registrationId}"
        provider:
          authorizationserver:
            authorization-uri: http://oauth2server:9999/oauth/authorize
            token-uri: http://oauth2server:9999/oauth/token
            user-info-uri: http://oauth2server:9999/me
            user-name-attribute: "name"
```





# 方法拦截

## Secured 方式

```java
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MethodSecurityConfig {
// ...
}
```

```java
public interface BankService {

@Secured("IS_AUTHENTICATED_ANONYMOUSLY")
public Account readAccount(Long id);

@Secured("IS_AUTHENTICATED_ANONYMOUSLY")
public Account[] findAccounts();

@Secured("ROLE_TELLER")
public Account post(Account account, double amount);
}
```

## PrePost 方式

```java
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class MethodSecurityConfig {
// ...
}
```

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
// ...
}
```

```java
public interface BankService {

@PreAuthorize("isAnonymous()")
public Account readAccount(Long id);

@PreAuthorize("isAnonymous()")
public Account[] findAccounts();

@PreAuthorize("hasAuthority('ROLE_TELLER')")
public Account post(Account account, double amount);
}
```

## 启用多种模式

```java
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig {
// ...
}
```

# ACL

[Domain Object Security ACL](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#domain-acls)

- `Acl`: Every domain object has one and only one `Acl` object, which internally holds the `AccessControlEntry` s as well as knows the owner of the `Acl`. An Acl does not refer directly to the domain object, but instead to an `ObjectIdentity`. The `Acl` is stored in the ACL_OBJECT_IDENTITY table.
- `AccessControlEntry`: An `Acl` holds multiple `AccessControlEntry` s, which are often abbreviated as ACEs in the framework. Each ACE refers to a specific tuple of `Permission`, `Sid` and `Acl`. An ACE can also be granting or non-granting and contain audit settings. The ACE is stored in the ACL_ENTRY table.
- `Permission`: A permission represents a particular immutable bit mask, and offers convenience functions for bit masking and outputting information. The basic permissions presented above (bits 0 through 4) are contained in the `BasePermission` class.
- `Sid`: The ACL module needs to refer to principals and `GrantedAuthority[]` s. A level of indirection is provided by the `Sid` interface, which is an abbreviation of "security identity". Common classes include `PrincipalSid` (to represent the principal inside an `Authentication` object) and `GrantedAuthoritySid`. The security identity information is stored in the ACL_SID table.
- `ObjectIdentity`: Each domain object is represented internally within the ACL module by an `ObjectIdentity`. The default implementation is called `ObjectIdentityImpl`.
- `AclService`: Retrieves the `Acl` applicable for a given `ObjectIdentity`. In the included implementation (`JdbcAclService`), retrieval operations are delegated to a `LookupStrategy`. The `LookupStrategy` provides a highly optimized strategy for retrieving ACL information, using batched retrievals (`BasicLookupStrategy`) and supporting custom implementations that leverage materialized views, hierarchical queries and similar performance-centric, non-ANSI SQL capabilities.
- `MutableAclService`: Allows a modified `Acl` to be presented for persistence. It is not essential to use this interface if you do not wish.

[ACL Schema](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#dbschema-acl)

```mysql
CREATE TABLE acl_sid (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    principal BOOLEAN NOT NULL,
    sid VARCHAR(100) NOT NULL,
    UNIQUE KEY unique_acl_sid (sid, principal)
) ENGINE=InnoDB;

CREATE TABLE acl_class (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    class VARCHAR(100) NOT NULL,
    UNIQUE KEY uk_acl_class (class)
) ENGINE=InnoDB;

CREATE TABLE acl_object_identity (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    object_id_class BIGINT UNSIGNED NOT NULL,
    object_id_identity VARCHAR(36) NOT NULL,
    parent_object BIGINT UNSIGNED,
    owner_sid BIGINT UNSIGNED,
    entries_inheriting BOOLEAN NOT NULL,
    UNIQUE KEY uk_acl_object_identity (object_id_class, object_id_identity),
    CONSTRAINT fk_acl_object_identity_parent FOREIGN KEY (parent_object) REFERENCES acl_object_identity (id),
    CONSTRAINT fk_acl_object_identity_class FOREIGN KEY (object_id_class) REFERENCES acl_class (id),
    CONSTRAINT fk_acl_object_identity_owner FOREIGN KEY (owner_sid) REFERENCES acl_sid (id)
) ENGINE=InnoDB;

CREATE TABLE acl_entry (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    acl_object_identity BIGINT UNSIGNED NOT NULL,
    ace_order INTEGER NOT NULL,
    sid BIGINT UNSIGNED NOT NULL,
    mask INTEGER UNSIGNED NOT NULL,
    granting BOOLEAN NOT NULL,
    audit_success BOOLEAN NOT NULL,
    audit_failure BOOLEAN NOT NULL,
    UNIQUE KEY unique_acl_entry (acl_object_identity, ace_order),
    CONSTRAINT fk_acl_entry_object FOREIGN KEY (acl_object_identity) REFERENCES acl_object_identity (id),
    CONSTRAINT fk_acl_entry_acl FOREIGN KEY (sid) REFERENCES acl_sid (id)
) ENGINE=InnoDB;
```

## 依赖

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-acl</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context-support</artifactId>
</dependency>
<dependency>
    <groupId>net.sf.ehcache</groupId>
    <artifactId>ehcache-core</artifactId>
    <version>2.6.11</version>
</dependency>
```

## AclConfig

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.sql.DataSource;

@Configuration
public class AclConfig {
    @Autowired
    DataSource dataSource;

    @Bean
    public MethodSecurityExpressionHandler
    defaultMethodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler
                = new DefaultMethodSecurityExpressionHandler();
        AclPermissionEvaluator permissionEvaluator
                = new AclPermissionEvaluator(aclService());
        expressionHandler.setPermissionEvaluator(permissionEvaluator);
        return expressionHandler;
    }

    @Bean
    public JdbcMutableAclService aclService() {
        return new JdbcMutableAclService(
                dataSource, lookupStrategy(), aclCache());
    }

    @Bean
    public AclAuthorizationStrategy aclAuthorizationStrategy() {
        return new AclAuthorizationStrategyImpl(
                new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Bean
    public PermissionGrantingStrategy permissionGrantingStrategy() {
        return new DefaultPermissionGrantingStrategy(
                new ConsoleAuditLogger());
    }

    @Bean
    public EhCacheBasedAclCache aclCache() {
        return new EhCacheBasedAclCache(
                aclEhCacheFactoryBean().getObject(),
                permissionGrantingStrategy(),
                aclAuthorizationStrategy()
        );
    }

    @Bean
    public EhCacheFactoryBean aclEhCacheFactoryBean() {
        EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();
        ehCacheFactoryBean.setCacheManager(aclCacheManager().getObject());
        ehCacheFactoryBean.setCacheName("aclCache");
        return ehCacheFactoryBean;
    }

    @Bean
    public EhCacheManagerFactoryBean aclCacheManager() {
        return new EhCacheManagerFactoryBean();
    }

    @Bean
    public LookupStrategy lookupStrategy() {
        return new BasicLookupStrategy(
                dataSource,
                aclCache(),
                aclAuthorizationStrategy(),
                new ConsoleAuditLogger()
        );
    }
}
```

## 方法控制

```java
@PostFilter("hasPermission(filterObject, 'READ')")
List<NoticeMessage> findAll();
    
@PostAuthorize("hasPermission(returnObject, 'READ')")
NoticeMessage findById(Integer id);
    
@PreAuthorize("hasPermission(#noticeMessage, 'WRITE')")
NoticeMessage save(@Param("noticeMessage")NoticeMessage noticeMessage);
```

## Acl API

```java
// Prepare the information we'd like in our access control entry (ACE)
ObjectIdentity oi = new ObjectIdentityImpl(Foo.class, new Long(44));
Sid sid = new PrincipalSid("Samantha");
Permission p = BasePermission.ADMINISTRATION;

// Create or update the relevant ACL
MutableAcl acl = null;
try {
acl = (MutableAcl) aclService.readAclById(oi);
} catch (NotFoundException nfe) {
acl = aclService.createAcl(oi);
}

// Now grant some permissions via an access control entry (ACE)
acl.insertAce(acl.getEntries().length, p, sid, true);
aclService.updateAcl(acl);
```



## 示例

[Spring Security ACL DEMO](https://www.baeldung.com/spring-security-acl)

## 说明

- Object 需要有 getId() 方法
- Sid 是角色名称或者 username
- 理论上可以实现字段级别的权限控制，需要对 AclPermissionEvaluator 进行定制
- `sidIdentityQuery` 和 `classIdentityQuery`需要根据数据库调整 SQL 语句，默认是 `call identity()`, sqlite 使用 "select seq from sqlite_sequence where name=<表名>"
- 需要自己写ACL分配的页面：允许还是拒绝, sid(useranme或者角色名), 对象（type, id),  permission , AclUtil 提供帮助
- 可以通过调用 AclPermissionEvaluator.setObjectIdentityGenerator 和  AclPermissionEvaluator.setObjectIdentityRetrievalStrategy 来替换 ObjectIdentity 的实现策略，比如实现对没有 getId 方法的对象，可以适配 getUserId 方法，以及对某一种类型的对象进行认证 

# Expression-Based Access Control

[Spring Security 5.4.2 el-access](https://docs.spring.io/spring-security/site/docs/5.4.2/reference/html5/#el-access)

| Expression                                                   | Description                                                  |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| `hasRole(String role)`                                       | Returns `true` if the current principal has the specified role.For example, `hasRole('admin')`By default if the supplied role does not start with 'ROLE_' it will be added. This can be customized by modifying the `defaultRolePrefix` on `DefaultWebSecurityExpressionHandler`. |
| `hasAnyRole(String… roles)`                                  | Returns `true` if the current principal has any of the supplied roles (given as a comma-separated list of strings).For example, `hasAnyRole('admin', 'user')`By default if the supplied role does not start with 'ROLE_' it will be added. This can be customized by modifying the `defaultRolePrefix` on `DefaultWebSecurityExpressionHandler`. |
| `hasAuthority(String authority)`                             | Returns `true` if the current principal has the specified authority.For example, `hasAuthority('read')` |
| `hasAnyAuthority(String… authorities)`                       | Returns `true` if the current principal has any of the supplied authorities (given as a comma-separated list of strings)For example, `hasAnyAuthority('read', 'write')` |
| `principal`                                                  | Allows direct access to the principal object representing the current user |
| `authentication`                                             | Allows direct access to the current `Authentication` object obtained from the `SecurityContext` |
| `permitAll`                                                  | Always evaluates to `true`                                   |
| `denyAll`                                                    | Always evaluates to `false`                                  |
| `isAnonymous()`                                              | Returns `true` if the current principal is an anonymous user |
| `isRememberMe()`                                             | Returns `true` if the current principal is a remember-me user |
| `isAuthenticated()`                                          | Returns `true` if the user is not anonymous                  |
| `isFullyAuthenticated()`                                     | Returns `true` if the user is not an anonymous or a remember-me user |
| `hasPermission(Object target, Object permission)`            | Returns `true` if the user has access to the provided target for the given permission. For example, `hasPermission(domainObject, 'read')` |
| `hasPermission(Object targetId, String targetType, Object permission)` | Returns `true` if the user has access to the provided target for the given permission. For example, `hasPermission(1, 'com.example.domain.Message', 'read')` |



# WebResponse

```java

public class WebResponse<T> {
    private T data;
    private int code;
    private String message;
    private String status;

    ////////////////////////////////////////////////////////////////////////////////
    ////
    public static <T> WebResponse<T> get(){
        return new WebResponse<>();
    }

    ////////////////////////////////////////////////////////////////////////////////
    ////

    public T getData() {
        return data;
    }

    public WebResponse<T> setData(T data) {
        this.data = data;
        return this;
    }

    public int getCode() {
        return code;
    }

    public WebResponse<T> setCode(int code) {
        this.code = code;
        return this;
    }

    public String getMessage() {
        return message;
    }

    public WebResponse<T> setMessage(String message) {
        this.message = message;
        return this;
    }

    public String getStatus() {
        return status;
    }

    public WebResponse<T> setStatus(String status) {
        this.status = status;
        return this;
    }
}
```

# AppUtil.java

```java
import com.github.iceant.spring.demo.util.convert.*;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.Locale;

@Component
public class AppUtil implements ApplicationContextAware {
    private static ApplicationContext applicationContext;

    //////////////////////////////////////////////////////////////////////
    ////
    public static <T> T bean(Class<T> type) {
        return applicationContext.getBean(type);
    }

    public static <T> T bean(String name) {
        return (T) applicationContext.getBean(name);
    }

    public static <T> T bean(Class<T> type, Object ... args){
        return applicationContext.getBean(type, args);
    }

    public static <T> T bean(String name, Object ... args) {
        return (T) applicationContext.getBean(name, args);
    }
    //////////////////////////////////////////////////////////////////////
    ////
    public static String propStr(String name, String def) {
        return applicationContext.getEnvironment().getProperty(name, def);
    }

    public static String propStr(String name) {
        return applicationContext.getEnvironment().getProperty(name);
    }

    public static Integer propInt(String name, Integer def) {
        String value = propStr(name, null);
        return new StringToInteger().convertFromAToB(name, def);
    }

    public static Integer propInt(String name) {
        String value = propStr(name, null);
        return new StringToInteger().convertFromAToB(name, null);
    }

    public static Long propLong(String name, Long def) {
        String value = propStr(name, null);
        return new StringToLong().convertFromAToB(name, def);
    }

    public static Long propLong(String name) {
        String value = propStr(name, null);
        return new StringToLong().convertFromAToB(name, null);
    }

    public static Short propShort(String name, Short def) {
        String value = propStr(name, null);
        return new StringToShort().convertFromAToB(name, def);
    }

    public static Short propShort(String name) {
        String value = propStr(name, null);
        return new StringToShort().convertFromAToB(name, null);
    }

    public static Float propFloat(String name, Float def) {
        String value = propStr(name, null);
        return new StringToFloat().convertFromAToB(name, def);
    }

    public static Float propFloat(String name) {
        String value = propStr(name, null);
        return new StringToFloat().convertFromAToB(name, null);
    }

    public static Double propDouble(String name, Double def) {
        String value = propStr(name, null);
        return new StringToDouble().convertFromAToB(name, def);
    }

    public static Double propDouble(String name) {
        String value = propStr(name, null);
        return new StringToDouble().convertFromAToB(name, null);
    }

    public static Number propNumber(String name, Number def) {
        String value = propStr(name, null);
        return new StringToNumber().convertFromAToB(value, def);
    }

    public static Number propNumber(String name, Number def, IConverter<String, Number> converter) {
        String value = propStr(name, null);
        return converter.convertFromAToB(value, def);
    }

    public static Date propDate(String name, Date def) {
        String value = propStr(name, null);
        return new StringToDate().convertFromAToB(value, def);
    }

    public static Date propTime(String name, Date def) {
        String value = propStr(name, null);
        return new StringToTime().convertFromAToB(value, def);
    }

    public static Date propDateTime(String name, Date def) {
        String value = propStr(name, null);
        return new StringToDateTime().convertFromAToB(value, def);
    }

    public static Date propDateTime(String name, Date def, IConverter<String, Date> converter) {
        String value = propStr(name, null);
        return converter.convertFromAToB(value, def);
    }

    public static Date propDate(String name, Date def, IConverter<String, Date> converter) {
        String value = propStr(name, null);
        return converter.convertFromAToB(value, def);
    }

    public static Date propTime(String name, Date def, IConverter<String, Date> converter) {
        String value = propStr(name, null);
        return converter.convertFromAToB(value, def);
    }

    //////////////////////////////////////////////////////////////////////
    ////
    public static HttpServletRequest servletRequest() {
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return servletRequestAttributes.getRequest();
    }

    public static HttpServletResponse servletResponse() {
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return servletRequestAttributes.getResponse();
    }

    public static ServletContext servletContext() {
        return servletRequest().getServletContext();
    }

    public static HttpSession httpSession() {
        return servletRequest().getSession();
    }

    public static HttpSession httpSession(boolean create) {
        return servletRequest().getSession(create);
    }

    public static Cookie[] httpCookies(){
        return servletRequest().getCookies();
    }

    public static Locale getLocale(){
        return LocaleContextHolder.getLocale();
    }

    public static Authentication getAuthentication(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static SecurityContext getSecurityContext(){
        return SecurityContextHolder.getContext();
    }
    //////////////////////////////////////////////////////////////////////
    ////
    public static String paramStr(String name, String def) {
        String value = servletRequest().getParameter(name);
        if (value == null) return def;
        return value;
    }

    public static String paramStr(String name) {
        return paramStr(name, null);
    }

    public static Integer paramInt(String name, Integer def) {
        String value = paramStr(name);
        return new StringToInteger().convertFromAToB(value, def);
    }

    public static Short paramShort(String name, Short def) {
        String value = paramStr(name);
        return new StringToShort().convertFromAToB(value, def);
    }

    public static Long paramLong(String name, Long def) {
        String value = paramStr(name);
        return new StringToLong().convertFromAToB(value, def);
    }

    public static Float paramFloat(String name, Float def) {
        String value = paramStr(name);
        return new StringToFloat().convertFromAToB(value, def);
    }

    public static Double paramDouble(String name, Double def) {
        String value = paramStr(name);
        return new StringToDouble().convertFromAToB(value, def);
    }

    public static Boolean paramBool(String name, Boolean def) {
        String value = paramStr(name);
        return new StringToBoolean().convertFromAToB(value, def);
    }

    public static Date paramDate(String name, Date def) {
        String value = paramStr(name);
        return new StringToDate().convertFromAToB(value, def);
    }

    public static Date paramTime(String name, Date def) {
        String value = paramStr(name);
        return new StringToTime().convertFromAToB(value, def);
    }

    public static Date paramDateTime(String name, Date def) {
        String value = paramStr(name);
        return new StringToDateTime().convertFromAToB(value, def);
    }

    public static Date paramDate(String name, Date def, IConverter<String, Date> converter) {
        String value = paramStr(name);
        return converter.convertFromAToB(value, def);
    }

    public static Number paramNumber(String name, Number def) {
        String value = paramStr(name);
        return new StringToNumber().convertFromAToB(value, def);
    }

    public static Number paramNumber(String name, Number def, IConverter<String, Number> converter) {
        String value = paramStr(name);
        return converter.convertFromAToB(value, def);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //// msg
    public static String msg(Locale locale, String name, Object ... args){
        return applicationContext.getMessage(name, args, locale);
    }

    public static String msg(Locale locale, String name, String defaultMessage, Object ... args){
        return applicationContext.getMessage(name, args, defaultMessage, locale);
    }

    public static String msg(String code, Object ... args){
        return applicationContext.getMessage(code, args, LocaleContextHolder.getLocale());
    }

    public static String msg(String code, String defaultMessage, Object ... args){
        return applicationContext.getMessage(code, args, defaultMessage, LocaleContextHolder.getLocale());
    }

    ////////////////////////////////////////////////////////////////////////////////
    ////
    @Override
    public void setApplicationContext(ApplicationContext ctx) throws BeansException {
        applicationContext = ctx;
    }
}
```

# BeanUtil

```java
package com.github.iceant.spring.demo.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class BeanUtil {

    public static Field findFieldInType(Class type, String name){
        if(type==null || name==null) return null;
        Field field = null;
        try {
            field = type.getDeclaredField(name);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
        }

        try {
            field = type.getField(name);
            field.setAccessible(true);
            return field;
        }catch (Exception err){}


        Class parentType = type.getSuperclass();
        if(parentType!=null){
            field = findFieldInType(parentType, name);
            if(field!=null){
                field.setAccessible(true);
                return field;
            }
        }

        Class[] interfaces = type.getInterfaces();
        if(interfaces!=null){
            for(Class itf : interfaces){
                field = findFieldInType(itf, name);
                if(field!=null){
                    field.setAccessible(true);
                    return field;
                }
            }
        }

        return null;
    }

    public static Method findMethodInType(Class type, String name, Class... params){
        if(type==null || name==null) return null;
        Method method = null;

        try {
            method = type.getDeclaredMethod(name, params);
            method.setAccessible(true);
            return method;
        } catch (NoSuchMethodException e) {
        }
        try {
            method = type.getMethod(name, params);
            method.setAccessible(true);
            return method;
        } catch (NoSuchMethodException e) {
        }

        Class parentType = type.getSuperclass();
        method = findMethodInType(parentType, name, params);
        if(method!=null){
            method.setAccessible(true);
            return method;
        }

        Class[] interfaces = type.getInterfaces();
        if(interfaces!=null){
            for(Class itf:interfaces){
                method = findMethodInType(itf, name, params);
                if(method!=null){
                    method.setAccessible(true);
                    return method;
                }
            }
        }

        for(Method m : type.getMethods()){
            if(m.getName().equals(name)){
                return m;
            }
        }

        return null;
    }

    public static Field findField(Object obj, String name){
        if(obj==null || name==null) return null;
        return findFieldInType(obj.getClass(), name);
    }

    public static Method findMethod(Object obj, String name, Class ... params){
        if(obj==null || name==null) return null;
        return findMethodInType(obj.getClass(), name, params);
    }

    public static <T> T invoke(Object obj, String methodName, Class[] params, Object ... args){
        Method method = findMethod(obj, methodName, params);
        if(method==null){
            throw new RuntimeException(new NoSuchMethodException(methodName));
        }

        try {
            return (T) method.invoke(obj, args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T invoke(Object obj, String methodName, Object ... args){
        Class[] params = null;
        if(args!=null){
            params = new Class[args.length];
            for(int i=0; i<args.length; i++){
                params[i] = args.getClass();
            }
        }
        Method method = findMethod(obj, methodName, params);
        if(method==null){
            throw new RuntimeException(new NoSuchMethodException(methodName));
        }

        try {
            return (T) method.invoke(obj, args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void set(Object obj, String fieldName, Object value){
        Field field = findField(obj, fieldName);
        if(field!=null){
            try {
                field.set(obj, value);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static <T> T get(Object obj, String fieldName, T def){
        Field field = findField(obj, fieldName);
        if(field==null) return def;
        try {
            field.get(obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return def;
    }

    public static String makeGetMethod(String fieldName){
        if(fieldName==null || fieldName.length()<1) return fieldName;
        return "get"+fieldName.substring(0, 1).toUpperCase()+fieldName.substring(1);
    }
    public static String makeSetMethod(String fieldName){
        if(fieldName==null || fieldName.length()<1) return fieldName;
        return "set"+fieldName.substring(0, 1).toUpperCase()+fieldName.substring(1);
    }

    public static <A,B> B copyAToB(A a, B b){
        if(a==null || b==null) return b;
        List<Method> getMethods = new ArrayList<>();

        for(Method method : a.getClass().getMethods()){
            String methodName = method.getName();
            if(method.getParameterCount()==0 && methodName.startsWith("get") && methodName.length()>3){
                Object value = null;
                Class returnType = method.getReturnType();
                try{
                    value =invoke(a, methodName);
                }catch (Exception err){}
                String setMethodName = "set"+methodName.substring(3);
                try {
                    invoke(b, setMethodName, new Class[]{returnType}, value);
                }catch (Exception err){}
            }
        }

        return b;
    }
}
```

# IConverter.java

```java
package com.github.iceant.spring.demo.util.convert;

public interface IConverter<A, B> {
    public B convertFromAToB(A a, B def);
}
```

# StringToBoolean.java

```java
package com.github.iceant.spring.demo.util.convert;

public class StringToBoolean implements IConverter<String, Boolean>{
    @Override
    public Boolean convertFromAToB(String s, Boolean def) {
        if(s==null) return def;
        try{
            return Boolean.valueOf(s);
        }catch (Exception err){}
        return def;
    }
}
```

# StringToDate.java

```java
package com.github.iceant.spring.demo.util.convert;

import java.text.DateFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class StringToDate implements IConverter<String, Date>{

    Integer dateStyle;
    Locale locale;
    Calendar calendar;
    Boolean lenient;
    TimeZone timeZone;
    NumberFormat numberFormat;
    String pattern;

    //////////////////////////////////////////////////////////////////////
    ////
    public DateFormat getDateFormat(){
        if(pattern!=null){
            return new SimpleDateFormat(pattern);
        }
        locale=(locale==null)?Locale.getDefault():locale;
        DateFormat dateFormat = DateFormat.getDateInstance(dateStyle, locale);
        if(calendar!=null) {
            dateFormat.setCalendar(calendar);
        }
        if(lenient!=null) {
            dateFormat.setLenient(lenient);
        }
        if(timeZone!=null) {
            dateFormat.setTimeZone(timeZone);
        }
        if(numberFormat!=null) {
            dateFormat.setNumberFormat(numberFormat);
        }

        return dateFormat;
    }

    //////////////////////////////////////////////////////////////////////
    ////
    @Override
    public Date convertFromAToB(String s, Date def) {
        if(s==null) return def;
        try{
            getDateFormat().parse(s);
        }catch (Exception err){ }
        return def;
    }

    //////////////////////////////////////////////////////////////////////
    ////

    public Integer getDateStyle() {
        return dateStyle;
    }

    public StringToDate setDateStyle(Integer dateStyle) {
        this.dateStyle = dateStyle;
        return this;
    }

    public Locale getLocale() {
        return locale;
    }

    public StringToDate setLocale(Locale locale) {
        this.locale = locale;
        return this;
    }

    public Calendar getCalendar() {
        return calendar;
    }

    public StringToDate setCalendar(Calendar calendar) {
        this.calendar = calendar;
        return this;
    }

    public Boolean getLenient() {
        return lenient;
    }

    public StringToDate setLenient(Boolean lenient) {
        this.lenient = lenient;
        return this;
    }

    public TimeZone getTimeZone() {
        return timeZone;
    }

    public StringToDate setTimeZone(TimeZone timeZone) {
        this.timeZone = timeZone;
        return this;
    }

    public NumberFormat getNumberFormat() {
        return numberFormat;
    }

    public StringToDate setNumberFormat(NumberFormat numberFormat) {
        this.numberFormat = numberFormat;
        return this;
    }
}
```

# StringToDateTime.java

```java
package com.github.iceant.spring.demo.util.convert;

import java.text.DateFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class StringToDateTime implements IConverter<String, Date>{
    Integer dateStyle;
    Integer timeStyle;
    Locale locale;
    Calendar calendar;
    Boolean lenient;
    TimeZone timeZone;
    NumberFormat numberFormat;
    String pattern;

    public DateFormat getDateFormat(){
        if(pattern!=null){
            return new SimpleDateFormat(pattern);
        }
        locale=(locale==null)? Locale.getDefault():locale;
        DateFormat dateFormat = DateFormat.getDateTimeInstance(dateStyle, timeStyle, locale);
        if(calendar!=null) {
            dateFormat.setCalendar(calendar);
        }
        if(lenient!=null) {
            dateFormat.setLenient(lenient);
        }
        if(timeZone!=null) {
            dateFormat.setTimeZone(timeZone);
        }
        if(numberFormat!=null) {
            dateFormat.setNumberFormat(numberFormat);
        }

        return dateFormat;
    }
    //////////////////////////////////////////////////////////////////////
    ////
    @Override
    public Date convertFromAToB(String s, Date def) {
        if(s==null) return def;
        try {
            return getDateFormat().parse(s);
        } catch (Exception e) {
        }
        return def;
    }
}
```

# StringToDouble.java

```java
package com.github.iceant.spring.demo.util.convert;

public class StringToDouble implements IConverter<String, Double>{
    @Override
    public Double convertFromAToB(String s, Double def) {
        if(s==null) return def;
        try{
            return Double.valueOf(s);
        }catch (Exception err){}
        return def;
    }
}
```

# StringToFloat.java

```java
package com.github.iceant.spring.demo.util.convert;

public class StringToFloat implements IConverter<String, Float>{
    @Override
    public Float convertFromAToB(String s, Float def) {
        if(s==null) return def;
        try{
            return Float.valueOf(s);
        }catch (Exception err){}
        return def;
    }
}
```

# StringToInteger.java

```java
package com.github.iceant.spring.demo.util.convert;

public class StringToInteger implements IConverter<String, Integer>{
    @Override
    public Integer convertFromAToB(String s, Integer def) {
        if(s==null) return def;
        try{
            return Integer.valueOf(s);
        }catch (Exception err){}
        return def;
    }
}
```

# StringToLong.java

```java
package com.github.iceant.spring.demo.util.convert;

public class StringToLong implements IConverter<String, Long> {
    @Override
    public Long convertFromAToB(String s, Long def) {
        if(s==null) return def;
        try{
            return Long.valueOf(s);
        }catch (Exception err){}
        return def;
    }
}
```

# StringToNumber.java

```java
package com.github.iceant.spring.demo.util.convert;

import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.util.Currency;
import java.util.Locale;

public class StringToNumber implements IConverter<String, Number>{
    Locale locale;
    Currency currency;
    DecimalFormatSymbols decimalFormatSymbols;
    Integer groupingSize;
    Boolean groupingUsed;
    Integer multiplier;
    Boolean decimalSeperatorAlwaysShown;
    Integer maximumFractionDigits;
    Integer minimumFractionDigits;
    Integer maximumIntegerDigits;
    Integer minimumIntegerDigit;
    String pattern;
    String negativePrefix;
    String negativeSuffix;
    Boolean parseBigDecimal;
    String positivePrefix;
    String positiveSuffix;
    RoundingMode roundingMode;

    //////////////////////////////////////////////////////////////////////
    ////
    public NumberFormat getNumberFormat(){
        locale = (locale==null)?Locale.getDefault():locale;
        DecimalFormat numberFormat = (DecimalFormat) NumberFormat.getNumberInstance(locale);
        if(currency!=null) {
            numberFormat.setCurrency(currency);
        }
        if(decimalFormatSymbols!=null) {
            numberFormat.setDecimalFormatSymbols(decimalFormatSymbols);
        }
        if(groupingSize!=null) {
            numberFormat.setGroupingSize(groupingSize);
        }
        if(groupingUsed!=null) {
            numberFormat.setGroupingUsed(groupingUsed);
        }
        if(multiplier!=null) {
            numberFormat.setMultiplier(multiplier);
        }
        if(decimalSeperatorAlwaysShown!=null) {
            numberFormat.setDecimalSeparatorAlwaysShown(decimalSeperatorAlwaysShown);
        }
        if(maximumFractionDigits!=null) {
            numberFormat.setMaximumFractionDigits(maximumFractionDigits);
        }
        if(maximumIntegerDigits!=null) {
            numberFormat.setMaximumIntegerDigits(maximumIntegerDigits);
        }
        if(minimumFractionDigits!=null) {
            numberFormat.setMinimumFractionDigits(minimumFractionDigits);
        }
        if(negativePrefix!=null) {
            numberFormat.setNegativePrefix(negativePrefix);
        }
        if(minimumIntegerDigit!=null) {
            numberFormat.setMinimumIntegerDigits(minimumIntegerDigit);
        }
        if(negativeSuffix!=null) {
            numberFormat.setNegativeSuffix(negativeSuffix);
        }
        if(parseBigDecimal!=null) {
            numberFormat.setParseBigDecimal(parseBigDecimal);
        }
        if(positivePrefix!=null) {
            numberFormat.setPositivePrefix(positivePrefix);
        }
        if(positiveSuffix!=null) {
            numberFormat.setPositiveSuffix(positiveSuffix);
        }
        if(roundingMode!=null) {
            numberFormat.setRoundingMode(roundingMode);
        }
        if(pattern!=null) {
            numberFormat.applyPattern(pattern);
        }
        return numberFormat;
    }

    //////////////////////////////////////////////////////////////////////
    ////
    @Override
    public Number convertFromAToB(String s, Number def) {
        if(s==null) return def;
        try {
            getNumberFormat().parse(s);
        }catch (Exception err){}
        return def;
    }

    //////////////////////////////////////////////////////////////////////
    ////


    public Currency getCurrency() {
        return currency;
    }

    public StringToNumber setCurrency(Currency currency) {
        this.currency = currency;
        return this;
    }

    public DecimalFormatSymbols getDecimalFormatSymbols() {
        return decimalFormatSymbols;
    }

    public StringToNumber setDecimalFormatSymbols(DecimalFormatSymbols decimalFormatSymbols) {
        this.decimalFormatSymbols = decimalFormatSymbols;
        return this;
    }

    public Integer getGroupingSize() {
        return groupingSize;
    }

    public StringToNumber setGroupingSize(Integer groupingSize) {
        this.groupingSize = groupingSize;
        return this;
    }

    public Boolean getGroupingUsed() {
        return groupingUsed;
    }

    public StringToNumber setGroupingUsed(Boolean groupingUsed) {
        this.groupingUsed = groupingUsed;
        return this;
    }

    public Integer getMultiplier() {
        return multiplier;
    }

    public StringToNumber setMultiplier(Integer multiplier) {
        this.multiplier = multiplier;
        return this;
    }

    public Boolean getDecimalSeperatorAlwaysShown() {
        return decimalSeperatorAlwaysShown;
    }

    public StringToNumber setDecimalSeperatorAlwaysShown(Boolean decimalSeperatorAlwaysShown) {
        this.decimalSeperatorAlwaysShown = decimalSeperatorAlwaysShown;
        return this;
    }

    public Integer getMaximumFractionDigits() {
        return maximumFractionDigits;
    }

    public StringToNumber setMaximumFractionDigits(Integer maximumFractionDigits) {
        this.maximumFractionDigits = maximumFractionDigits;
        return this;
    }

    public Integer getMinimumFractionDigits() {
        return minimumFractionDigits;
    }

    public StringToNumber setMinimumFractionDigits(Integer minimumFractionDigits) {
        this.minimumFractionDigits = minimumFractionDigits;
        return this;
    }

    public Integer getMaximumIntegerDigits() {
        return maximumIntegerDigits;
    }

    public StringToNumber setMaximumIntegerDigits(Integer maximumIntegerDigits) {
        this.maximumIntegerDigits = maximumIntegerDigits;
        return this;
    }

    public Integer getMinimumIntegerDigit() {
        return minimumIntegerDigit;
    }

    public StringToNumber setMinimumIntegerDigit(Integer minimumIntegerDigit) {
        this.minimumIntegerDigit = minimumIntegerDigit;
        return this;
    }

    public String getNegativePrefix() {
        return negativePrefix;
    }

    public StringToNumber setNegativePrefix(String negativePrefix) {
        this.negativePrefix = negativePrefix;
        return this;
    }

    public String getNegativeSuffix() {
        return negativeSuffix;
    }

    public StringToNumber setNegativeSuffix(String negativeSuffix) {
        this.negativeSuffix = negativeSuffix;
        return this;
    }

    public Boolean getParseBigDecimal() {
        return parseBigDecimal;
    }

    public StringToNumber setParseBigDecimal(Boolean parseBigDecimal) {
        this.parseBigDecimal = parseBigDecimal;
        return this;
    }

    public String getPositivePrefix() {
        return positivePrefix;
    }

    public StringToNumber setPositivePrefix(String positivePrefix) {
        this.positivePrefix = positivePrefix;
        return this;
    }

    public String getPositiveSuffix() {
        return positiveSuffix;
    }

    public StringToNumber setPositiveSuffix(String positiveSuffix) {
        this.positiveSuffix = positiveSuffix;
        return this;
    }

    public RoundingMode getRoundingMode() {
        return roundingMode;
    }

    public StringToNumber setRoundingMode(RoundingMode roundingMode) {
        this.roundingMode = roundingMode;
        return this;
    }

    public String getPattern() {
        return pattern;
    }

    public StringToNumber setPattern(String pattern) {
        this.pattern = pattern;
        return this;
    }

    public Locale getLocale() {
        return locale;
    }

    public StringToNumber setLocale(Locale locale) {
        this.locale = locale;
        return this;
    }
}
```

# StringToShort.java

```java
package com.github.iceant.spring.demo.util.convert;

public class StringToShort implements IConverter<String, Short>{
    @Override
    public Short convertFromAToB(String s, Short def) {
        if(s==null) return def;
        try{
            return Short.valueOf(s);
        }catch (Exception err){}
        return def;
    }
}
```

# StringToTime.java

```java
package com.github.iceant.spring.demo.util.convert;

import java.text.DateFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class StringToTime implements IConverter<String, Date>{
    Integer timeStyle;
    Locale locale;
    Calendar calendar;
    Boolean lenient;
    TimeZone timeZone;
    NumberFormat numberFormat;
    String pattern;

    //////////////////////////////////////////////////////////////////////
    ////
    public DateFormat getDateFormat(){
        if(pattern!=null){
            return new SimpleDateFormat(pattern);
        }
        locale=(locale==null)?Locale.getDefault():locale;
        DateFormat dateFormat = DateFormat.getTimeInstance(timeStyle, locale);
        if(calendar!=null) {
            dateFormat.setCalendar(calendar);
        }
        if(lenient!=null) {
            dateFormat.setLenient(lenient);
        }
        if(timeZone!=null) {
            dateFormat.setTimeZone(timeZone);
        }
        if(numberFormat!=null) {
            dateFormat.setNumberFormat(numberFormat);
        }

        return dateFormat;
    }

    //////////////////////////////////////////////////////////////////////
    ////
    @Override
    public Date convertFromAToB(String s, Date def) {
        if(s==null) return def;
        try{
            return getDateFormat().parse(s);
        }catch (Exception err){}
        return def;
    }

    //////////////////////////////////////////////////////////////////////
    ////
    public Integer getTimeStyle() {
        return timeStyle;
    }

    public StringToTime setTimeStyle(Integer timeStyle) {
        this.timeStyle = timeStyle;
        return this;
    }

    public Locale getLocale() {
        return locale;
    }

    public StringToTime setLocale(Locale locale) {
        this.locale = locale;
        return this;
    }

    public Calendar getCalendar() {
        return calendar;
    }

    public StringToTime setCalendar(Calendar calendar) {
        this.calendar = calendar;
        return this;
    }

    public Boolean getLenient() {
        return lenient;
    }

    public StringToTime setLenient(Boolean lenient) {
        this.lenient = lenient;
        return this;
    }

    public TimeZone getTimeZone() {
        return timeZone;
    }

    public StringToTime setTimeZone(TimeZone timeZone) {
        this.timeZone = timeZone;
        return this;
    }

    public NumberFormat getNumberFormat() {
        return numberFormat;
    }

    public StringToTime setNumberFormat(NumberFormat numberFormat) {
        this.numberFormat = numberFormat;
        return this;
    }

    public String getPattern() {
        return pattern;
    }

    public StringToTime setPattern(String pattern) {
        this.pattern = pattern;
        return this;
    }
}
```

# AclUtil

```java
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.List;

public class AclUtil {

    ////////////////////////////////////////////////////////////////////////////////
    ////
    public static final int PERMISSION_READ = 1;
    public static final int PERMISSION_WRITE = 1 << 1;
    public static final int PERMISSION_CREATE = 1 << 2;
    public static final int PERMISSION_DELETE = 1 << 3;
    public static final int PERMISSION_ADMIN = 1 << 4;


    ////////////////////////////////////////////////////////////////////////////////
    ////

    public static Acl grant(Sid sid, ObjectIdentity oid, Permission permission) {
        return assign(sid, oid, permission, true);
    }

    public static Acl deny(Sid sid, ObjectIdentity oid, Permission permission) {
        return assign(sid, oid, permission, false);
    }

    public static Acl assign(Sid sid, ObjectIdentity oid, Permission permission, Boolean granting) {
        MutableAclService aclService = AppUtil.bean(MutableAclService.class);
        if (aclService == null) return null;
        MutableAcl mutableAcl = null;
        try {
            mutableAcl = (MutableAcl) aclService.readAclById(oid);
        } catch (NotFoundException nfe) {
            mutableAcl = aclService.createAcl(oid);
        }
        mutableAcl.insertAce(mutableAcl.getEntries().size(), permission, sid, granting);
        aclService.updateAcl(mutableAcl);
        return mutableAcl;
    }

    public static Acl withdraw(Sid sid, ObjectIdentity oid, Permission permission) {
        MutableAclService aclService = AppUtil.bean(MutableAclService.class);
        if (aclService == null) return null;
        MutableAcl mutableAcl = null;
        try {
            mutableAcl = (MutableAcl) aclService.readAclById(oid);
        } catch (NotFoundException nfe) {
            return null;
        }
        List<AccessControlEntry> accessControlEntryList = mutableAcl.getEntries();
        AccessControlEntry foundAce = null;
        for (int i = 0; i < accessControlEntryList.size(); i++) {
            AccessControlEntry ace = accessControlEntryList.get(i);
            if (ace.getSid().equals(sid) && ace.getPermission().equals(permission)) {
                foundAce = ace;
                break;
            }
        }
        if (foundAce != null) {
            mutableAcl = aclService.updateAcl(mutableAcl);
        }
        return mutableAcl;
    }

    public static Boolean hasPermission(Authentication authentication, Serializable objectId, String objectType, Permission permission) {
        PermissionEvaluator permissionEvaluator = AppUtil.bean(PermissionEvaluator.class);
        return permissionEvaluator.hasPermission(authentication, objectId, objectType, permission);
    }

    public static Boolean hasPermission(Authentication authentication, ObjectIdentity oid, Permission permission) {
        PermissionEvaluator permissionEvaluator = AppUtil.bean(PermissionEvaluator.class);
        return permissionEvaluator.hasPermission(authentication, oid.getIdentifier(), oid.getType(), permission);
    }

    ////////////////////////////////////////////////////////////////////////////////
    ////

    public static Sid makePrincipalSid(String id) {
        return new PrincipalSid(id);
    }

    public static Sid makePrincipalSid(Authentication authentication) {
        return new PrincipalSid(authentication);
    }

    public static Sid getPrincipalSid() {
        return new PrincipalSid(AppUtil.getAuthentication());
    }

    public static Sid makeGrantedAuthoritySid(String grantedAuthority) {
        return new GrantedAuthoritySid(grantedAuthority);
    }

    public static Sid makeGrantedAuthoritySid(GrantedAuthority grantedAuthority) {
        return new GrantedAuthoritySid(grantedAuthority);
    }

    public static ObjectIdentity makeObjectIdentity(Object type, Serializable id) {
        return new ObjectIdentityImpl(type.getClass(), id);
    }

    public static ObjectIdentity makeObjectIdentity(String type, Serializable id) {
        return new ObjectIdentityImpl(type.getClass(), id);
    }

    public static ObjectIdentity makeObjectIdentity(Class type, Serializable id) {
        return new ObjectIdentityImpl(type, id);
    }

    public static Permission makePermission(int mask) {
        switch (mask) {
            case 1:
                return BasePermission.READ;
            case 1 << 1:
                return BasePermission.WRITE;
            case 1 << 2:
                return BasePermission.CREATE;
            case 1 << 3:
                return BasePermission.DELETE;
            case 1 << 4:
                return BasePermission.ADMINISTRATION;
            default:
                throw new IllegalArgumentException(String.valueOf(mask));
        }
    }
}
```

