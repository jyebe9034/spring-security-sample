package com.example.sec.config;

import com.example.sec.service.MemberService;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter { // WebSecurityConfigurerAdapter는 WebSecurityConfigurer 인스턴스를 쉽게 생성하기 위한 클래

    private MemberService memberService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // BCryptPasswordEncoder는 spring security에서 제공하는 비밀번호 암호화 객체
    }

    @Override
    public void configure(WebSecurity web) throws Exception { // WebSecurity는 FilterChainProxy를 생성하는 필터
        // resource/static directory의 하위 파일 목록은 인증 무시(항상 통과)
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception { // HttpSecurity를 통해 웹 기반의 보안 구성이 가능함.
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/myinfo").hasRole("Member")
                .antMatchers("/**").permitAll()
                .and()
                .formLogin() // form기반 인증. 로그인 정보는 기본적으로 HTTPSession 을 이용.
                .loginPage("/user/login") // 커스텀된 로그인 폼을 이용하고 싶은 경우 사용.
                .defaultSuccessUrl("/user/login/result")
                .permitAll()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/user/logout")) // 로그아웃의 기본 url("/logout")이 아 다른 url로 재정의.
                .logoutSuccessUrl("/user/logout/result")
                .invalidateHttpSession(true) // http 세션 초기화
                .and()
                .exceptionHandling().accessDeniedPage("/user/denied");
    }

    /* 스프링 시큐리티에서의 모든 인증은 AuthenticationManager를 통해 이루어 지며
    *  AuthenticationManager를 생성하기 위해 AuthenticationManagerBuilder를 사용 */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 로그인 처리, 즉 인증을 위해서는 UserDetailService를 통해 정보를 가져오는데 memberService가 UserDetailService를 구현하도록 함.
        auth.userDetailsService(memberService).passwordEncoder(passwordEncoder()); // 비밀번호 암호화를 위해 passwordEncoder()를 사용함.
    }

}
