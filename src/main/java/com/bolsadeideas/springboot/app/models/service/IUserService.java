package com.bolsadeideas.springboot.app.models.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bolsadeideas.springboot.app.models.dao.IUserDao;
import com.bolsadeideas.springboot.app.models.entity.Autorithy;
import com.bolsadeideas.springboot.app.models.entity.User;

@Service("IUserService")
public class IUserService implements UserDetailsService {

	@Autowired
	private IUserDao userDao;

	private final Logger log = LoggerFactory.getLogger(getClass());

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user = userDao.findByUsername(username);

		if (user == null) {
			log.info("Error en el login : no existe el usuario: " + username + "");
			throw new UsernameNotFoundException("The user: " + username + " no exist in the system..");
		}

		List<GrantedAuthority> autorithies = new ArrayList<GrantedAuthority>();

		for (Autorithy role : user.getRoles()) {
			autorithies.add(new SimpleGrantedAuthority(role.getAuthority()));
		}

		if (autorithies.isEmpty()) {
			log.info("Error en el login : el usuario: " + username + " no tiene roles");
			throw new UsernameNotFoundException("The user: " + username + " don't have autorities");
		}

		return new org.springframework.security.core.userdetails.User(username, user.getPassword(), user.isEnabled(),
				true, true, true, autorithies);
	}

}
