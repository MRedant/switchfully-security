package com.cegeka.switchfully.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPoint authEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,ArmyResource.ARMY_RESOURCE_PATH).hasRole("CIVILIAN")
                .antMatchers(ArmyResource.ARMY_RESOURCE_PATH+"/promote/**").hasRole("HUMAN_RELATIONSHIPS")
                .antMatchers(ArmyResource.ARMY_RESOURCE_PATH+"/discharge/**").hasRole("HUMAN_RELATIONSHIPS")
                .antMatchers(ArmyResource.ARMY_RESOURCE_PATH+"/nuke/**").hasRole("GENERAL")
                .antMatchers(ArmyResource.ARMY_RESOURCE_PATH+"/**").hasAnyRole("PRIVATE","GENERAL")
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().httpBasic()
                .authenticationEntryPoint(authEntryPoint);
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("ZWANETTA").password("WORST").roles("CIVILIAN")
                .and()
                .withUser("JMILLER").password("THANKS").roles("PRIVATE")
                .and()
                .withUser("UNCLE").password("SAM").roles("HUMAN_RELATIONSHIPS","PRIVATE")
                .and()
                .withUser("GENNY").password("RALLY").roles("GENERAL");
    }

}
