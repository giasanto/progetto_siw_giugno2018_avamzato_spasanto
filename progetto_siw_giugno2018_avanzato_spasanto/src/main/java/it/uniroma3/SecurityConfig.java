package it.uniroma3;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final String usersQuery = "SELECT username,password,TRUE FROM utenti WHERE username = ?";
	private final String rolesQuery = "SELECT username,role FROM utenti WHERE username = ?";

	@Qualifier("dataSource")
	@Autowired
	private DataSource dataSource;

	@Autowired
	private AccessDeniedHandler accessDeniedHandler;

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource)
		.passwordEncoder(new BCryptPasswordEncoder())
		.usersByUsernameQuery(usersQuery)
		.authoritiesByUsernameQuery(rolesQuery);
	}

	@Override
	public void configure(WebSecurity web) {
		web
		.ignoring()
		.antMatchers("/static/**", "/css/**", "/images/**", "/js/**", "/vendor/**");
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource)
		.passwordEncoder(bCryptPasswordEncoder())
		.usersByUsernameQuery(usersQuery)
		.authoritiesByUsernameQuery(rolesQuery);
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable()
		.authorizeRequests()
		.antMatchers("/", "/index", "/login").permitAll()             // possono accedere tutti a queste risorse
		.antMatchers("/admin/**").hasRole("ADMIN")              // /admin/** accessibile solo a utenti con ruolo ADMIN
		.antMatchers("/user/**").hasRole("USER")                     // /user/** accessibile solo a utenti con ruolo USER
		.anyRequest().permitAll()
		.anyRequest().authenticated()
		.and()
		.formLogin()
		.loginPage("/login") 					// pagina di login	
		.defaultSuccessUrl("/role")
		.and()
		.logout()
		.logoutSuccessUrl("/login")
		.permitAll()
		.and()
		.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
	}
}
