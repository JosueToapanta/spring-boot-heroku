package com.bolsadeideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.bolsadeideas.springboot.app.auth.handler.LoginSuccesHandler;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

// import javax.sql.DataSource;
// import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private LoginSuccesHandler succesHandler;

    @Autowired
    private JpaUserDetailsService userDetailsService;

    // @Autowired
    // private DataSource dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar/**", "/locale", "/api/clientes/**").permitAll()
                /*
                 * .antMatchers("/ver/**").hasAnyRole("USER")
                 * .antMatchers("/uploads/**").hasAnyRole("USER")
                 * .antMatchers("/form/**").hasAnyRole("ADMIN")
                 * .antMatchers("/eliminar/**").hasAnyRole("ADMIN")
                 * .antMatchers("/factura/**").hasAnyRole("ADMIN")
                 */
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .successHandler(succesHandler)
                .loginPage("/login")
                .permitAll()
                .and()
                .logout().permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/error_403");

        return http.build();

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder build) throws Exception {
        build.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);

        // build.jdbcAuthentication()
        // .dataSource(dataSource)
        // .passwordEncoder(passwordEncoder)
        // .usersByUsernameQuery("select username, password, enabled from users where
        // username=?")
        // .authoritiesByUsernameQuery(
        // "select u.username, a.authority from authorities a inner join users u on
        // (a.user_id=u.id) where u.username=?");
    }

    // @Bean
    // public UserDetailsService userDetailsService() throws Exception {

    // InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    // manager.createUser(User
    // .withUsername("user")
    // .password(this.passwordEncoder.encode("user"))
    // .roles("USER")
    // .build());
    // manager.createUser(User
    // .withUsername("admin")
    // .password(this.passwordEncoder.encode("admin"))
    // .roles("ADMIN", "USER")
    // .build());

    // return manager;
    // }

}
