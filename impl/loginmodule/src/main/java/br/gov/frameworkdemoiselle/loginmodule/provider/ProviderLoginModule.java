package br.gov.frameworkdemoiselle.loginmodule.provider;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.gov.frameworkdemoiselle.loginmodule.AuthException;
import br.gov.frameworkdemoiselle.loginmodule.JACCRequestUtil;
import br.gov.frameworkdemoiselle.loginmodule.Role;
import br.gov.frameworkdemoiselle.loginmodule.SimpleGroup;
import br.gov.frameworkdemoiselle.loginmodule.message.IThrowableHandler;

public class ProviderLoginModule implements LoginModule {
	private static final String OPTION_AUTHENTICATION_PROVIDER_CLASS = "authentication-provider-class";
	private static final String OPTION_AUTHORIZATION_PROVIDER_CLASS = "authorization-provider-class";
	private static final String OPTION_THROWABLE_HANDLER_CLASS = "throwable-handler-class";
	private static final String STATE_LOGIN_NAME = "javax.security.auth.login.name";
	private static final String STATE_LOGIN_PASSWORD = "javax.security.auth.login.password";
	private static final String STATE_LOGIN_CERTIFICATE = "javax.security.auth.login.certificate";
	public static final String USERNAME = "username";
	public static final String PASSWORD = "password";
	public static final String NEW_PASSWORD = "newPassword";
	public static final String X509 = "X509";
	public static final String USER_PASSWORD = "username-password";
	public static final String CLIENT_CERTIFICATE = "client-certificate";
	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map<String, Object> sharedState;
	private Map<String, Object> options;
	private IAuthenticationProvider authentication;
	private IAuthorizationProvider authorization;
	private IThrowableHandler throwableHandler;
	private Principal callerPrincipal;
	private Properties publicOptions;
	
	private Logger logger;

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map sharedState, Map options) {
		
		this.logger = LoggerFactory.getLogger(ProviderLoginModule.class);
		
		logger.info("initialize");
		
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;

		processOptions();
	}

	public boolean login() throws LoginException {
		logger.info("login");

		NameCallback nc = new NameCallback("Authentication type: ");

		PasswordCallback pc = new PasswordCallback("Password: ", false);

		Callback[] callbacks = new Callback[] { nc, pc };

		try {
			callbackHandler.handle(callbacks);

		} catch (Exception e) {
			logger.error("Error on Callback Handle : " + e.getMessage());

			throw new RuntimeException("Error on Callback Handle", e);
		}

		JACCRequestUtil requestUtil = new JACCRequestUtil();

		if (nc.getName().equals(USER_PASSWORD)) {
			String username = (String) requestUtil.getRequest().getAttribute(
					USERNAME);

			String password = (String) requestUtil.getRequest().getAttribute(
					PASSWORD);

			String newPassword = (String) requestUtil.getRequest()
					.getAttribute(NEW_PASSWORD);

			authentication.initialize(publicOptions);

			try {
				if (newPassword.trim().length() == 0) {
					callerPrincipal = authentication.authenticate(username,
							password);
				} else {
					callerPrincipal = authentication.authenticate(username,
							password, newPassword);
				}
			} catch (Throwable t) {
				throwableHandler.handle(t);
			}

			if (callerPrincipal != null && !(callerPrincipal instanceof Error)) {
				sharedState.put(STATE_LOGIN_NAME, username);
				sharedState.put(STATE_LOGIN_PASSWORD, password);

				return true;
			} else {
				return false;
			}
		} else if (nc.getName().equals(CLIENT_CERTIFICATE)) {
			X509Certificate cert = (X509Certificate) requestUtil.getRequest()
					.getAttribute(X509);

			authentication.initialize(publicOptions);

			try {
				callerPrincipal = authentication.authenticate(cert);
			} catch (Throwable t) {
				throwableHandler.handle(t);
			}

			if (callerPrincipal != null) {
				sharedState.put(STATE_LOGIN_CERTIFICATE, cert);

				return true;
			} else {
				return false;
			}
		} else {
			throw new AuthException("Authentication type " + nc.getName()
					+ " is invalid.");
		}
	}

	public boolean logout() throws LoginException {
		logger.info("logout");
		
		JACCRequestUtil requestUtil = new JACCRequestUtil();

		requestUtil.getRequest().getSession().invalidate();

		return true;
	}

	public boolean commit() throws LoginException {
		logger.info("commit");
		
		SimpleGroup callerPrincipalGroup;
		SimpleGroup roleGroup;
		Collection<Role> roles;

		authorization.initialize(publicOptions);

		roles = authorization.authorize(callerPrincipal);

		callerPrincipalGroup = new SimpleGroup("CallerPrincipal");

		callerPrincipalGroup.addMember(callerPrincipal);

		subject.getPrincipals().add(callerPrincipalGroup);

		roleGroup = new SimpleGroup("Roles");

		for (Role role : roles) {
			roleGroup.addMember(role);
		}

		subject.getPrincipals().add(roleGroup);

		return true;
	}

	public boolean abort() throws LoginException {
		logger.info("abort");
		
		return true;
	}

	private void processOptions() {
		logger.info("Processing options");

		// OPTION_AUTHENTICATION_PROVIDER_CLASS
		String optionAuthenticationClass = (String) options
				.get(OPTION_AUTHENTICATION_PROVIDER_CLASS);

		logger.info("Processing options: " + OPTION_AUTHENTICATION_PROVIDER_CLASS + " - " + optionAuthenticationClass);
		if (optionAuthenticationClass == null) {
			throw new AuthException("Option "
					+ OPTION_AUTHENTICATION_PROVIDER_CLASS + " not found");
		}

		try {
			Class<IAuthenticationProvider> clazz = (Class<IAuthenticationProvider>) Class
					.forName(optionAuthenticationClass);
			authentication = clazz.newInstance();
		} catch (Exception e) {
			throw new AuthException("Invalid value of option "
					+ OPTION_AUTHENTICATION_PROVIDER_CLASS, e);
		}


		// OPTION_AUTHORIZATION_PROVIDER_CLASS

		String optionAthorizationClass = (String) options
				.get(OPTION_AUTHORIZATION_PROVIDER_CLASS);		
		logger.info("Processing options: " + OPTION_AUTHORIZATION_PROVIDER_CLASS + " - " + optionAthorizationClass);
		
		if (optionAthorizationClass.equals(optionAuthenticationClass)) {
			if (authentication instanceof IAuthorizationProvider) {
				authorization = (IAuthorizationProvider) authentication;
			} else {
				throw new AuthException("Class [" + OPTION_AUTHORIZATION_PROVIDER_CLASS + "] does not implements IAuthorizationProvider");
			}			
		} else {
			if (optionAthorizationClass == null) {
				throw new AuthException("Option "+OPTION_AUTHORIZATION_PROVIDER_CLASS+" not found");
			}
			try {
		 		Class<IAuthorizationProvider> clazz = (Class<IAuthorizationProvider>) Class.forName(optionAthorizationClass);
		 		authorization = clazz.newInstance();
		 	} catch (Exception e) {
		 		throw new AuthException("Invalid value of option "+OPTION_AUTHORIZATION_PROVIDER_CLASS, e);
		 	}
		 }
		
		
		// OPTION_THROWABLE_HANDLER_CLASS
		String optionThrowableHandlerClass = (String) options
				.get(OPTION_THROWABLE_HANDLER_CLASS);
		
		logger.info("Processing options: " + OPTION_THROWABLE_HANDLER_CLASS + " - " + optionThrowableHandlerClass);
		if (optionThrowableHandlerClass == null) {
			throw new AuthException("Option " + OPTION_THROWABLE_HANDLER_CLASS
					+ " not found");
		}

		if (optionThrowableHandlerClass != null) {
			try {
				Class<IThrowableHandler> clazz = (Class<IThrowableHandler>) Class
						.forName(optionThrowableHandlerClass);
				throwableHandler = clazz.newInstance();
			} catch (Exception e) {
				throw new AuthException("Invalid value of option "
						+ OPTION_THROWABLE_HANDLER_CLASS, e);
			}
		}
		createPublicOptions();
	}

	/**
	 * Remove Provider Login Module options of public options
	 */
	private void createPublicOptions() {
		logger.info("create public options");

		publicOptions = new Properties();
		for (String key : options.keySet()) {
			if (key.equals(OPTION_AUTHENTICATION_PROVIDER_CLASS))
				continue;
			if (key.equals(OPTION_AUTHORIZATION_PROVIDER_CLASS))
				continue;
			if (key.equals(OPTION_THROWABLE_HANDLER_CLASS))
				continue;

			logger.info("Processing options: " + key + " - " + options.get(key));

			publicOptions.put(key, options.get(key));
		}
	}
}
