package talan.fraudManagement.gatewayservice.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity 	
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private JwtConfig JwtConfig;
 
	@Override
  	protected void configure(HttpSecurity http) throws Exception {
    	   http
		.csrf().disable()
		    
	 	    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 	
		.and()
		   
		    .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)) 	
		.and()
		   
		   .addFilterAfter(new JwtTokenAuthenticationFilter(JwtConfig), UsernamePasswordAuthenticationFilter.class)
		
		.authorizeRequests()
		       // allow all who are accessing "auth" service
		   .antMatchers(HttpMethod.POST, JwtConfig.getUri()).permitAll()  
           //  .antMatchers("/auth/**").permitAll()
		    // must be an admin if trying to access admin area (authentication is also required here)
		   .antMatchers("/command" + "/admin/**").hasRole("ADMIN")
//		   .antMatchers("/command").hasRole("USER")
		  // .antMatchers("/command").permitAll()
		  
		  // Any other request must be authenticated
		   .anyRequest().authenticated(); 
	}
	
	@Bean
  	public JwtConfig JwtConfig() {
    	   return new JwtConfig();
  	}
	
}

