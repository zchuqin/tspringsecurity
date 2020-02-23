package stoner.tspringsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.DigestUtils;
import stoner.tspringsecurity.handler.MyPasswordEncoder;
import stoner.tspringsecurity.service.UserService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Autowired
    private MyPasswordEncoder myPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(myPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors();
        http.formLogin().loginProcessingUrl("/user/login")
                .successHandler(getAuthenticationSuccessHandler())
                .failureHandler(getAuthenticationFailureHandler())
                .usernameParameter("username").passwordParameter("password").permitAll()
                .and().authorizeRequests()
                .antMatchers("/admin/**").hasRole("系统管理员")
                .antMatchers("/admin/**").hasIpAddress("127.0.0.1")
                .antMatchers("/admin/**").access("@userService.hasPermission(request,authentication)")
                .anyRequest().authenticated()
                .and().logout().logoutUrl("/logout").logoutSuccessHandler(getLogoutSuccessHandler()).permitAll()
                .and().csrf().disable()
                .exceptionHandling().accessDeniedHandler(getAccessDeniedHandler());

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/v2/api-docs", "/configuration/ui", "/swagger-resources", "/configuration/security", "/swagger-ui.html", "/webjars/**","/swagger-resources/configuration/ui","/index.html","/static/**");
    }

    private AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
        return (httpServletRequest, httpServletResponse, authentication) -> {
            httpServletResponse.setContentType("application/json;charset=utf-8");
            PrintWriter out = httpServletResponse.getWriter();
            out.write("{\"status\":\"success\",\"msg\":\"登录成功\"}");
            out.flush();
            out.close();
        };
    }

    private AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return (httpServletRequest, httpServletResponse, e) -> {
            log.error(e.getMessage());
            httpServletResponse.setContentType("application/json;charset=utf-8");
            PrintWriter out = httpServletResponse.getWriter();
            out.write("{\"status\":\"error\",\"msg\":\"登录失败\"}");
            out.flush();
            out.close();
        };
    }

    private LogoutSuccessHandler getLogoutSuccessHandler() {
        return (httpServletRequest, httpServletResponse, authentication) -> {
            httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpServletResponse.setCharacterEncoding("UTF-8");
            PrintWriter out = httpServletResponse.getWriter();
            out.write("成功注销!");
            out.flush();
            out.close();
        };
    }

    private AccessDeniedHandler getAccessDeniedHandler() {
        return (httpServletRequest, httpServletResponse, e) -> {
            log.error(e.getMessage());
            httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpServletResponse.setCharacterEncoding("UTF-8");
            PrintWriter out = httpServletResponse.getWriter();
            out.write("权限不足!");
            out.flush();
            out.close();
        };
    }
}
