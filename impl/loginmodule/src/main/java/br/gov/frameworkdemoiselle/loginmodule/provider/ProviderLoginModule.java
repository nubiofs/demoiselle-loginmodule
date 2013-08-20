package br.gov.frameworkdemoiselle.loginmodule.provider;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

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

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        processOptions();
    }

    public boolean login() throws LoginException {
        NameCallback nc = new NameCallback("Authentication type: ");

        PasswordCallback pc = new PasswordCallback("Password: ", false);

        Callback[] callbacks = new Callback[]{nc, pc};

        try {
            callbackHandler.handle(callbacks);

            System.out.println(nc.getName());
        } catch (Exception e) {
            throw new RuntimeException("Error on Callback Handle", e);
        }

        JACCRequestUtil requestUtil = new JACCRequestUtil();

        if (nc.getName().equals(USER_PASSWORD)) {
            String username = (String) requestUtil.getRequest().getAttribute(USERNAME);

            String password = (String) requestUtil.getRequest().getAttribute(PASSWORD);

            String newPassword = (String) requestUtil.getRequest().getAttribute(NEW_PASSWORD);

            authentication.initialize(null);

            try {
                if (newPassword.trim().length() == 0) {
                    callerPrincipal = authentication.authenticate(username, password);
                } else {
                    callerPrincipal = authentication.authenticate(username, password, newPassword);
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
            X509Certificate cert = (X509Certificate) requestUtil.getRequest().getAttribute(X509);

            authentication.initialize(null);

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
            throw new AuthException("Authentication type " + nc.getName() + " is invalid.");
        }
    }

    public boolean logout() throws LoginException {
        System.out.println("Logout");

        JACCRequestUtil requestUtil = new JACCRequestUtil();

        requestUtil.getRequest().getSession().invalidate();

        return true;
    }

    public boolean commit() throws LoginException {
        System.out.println("Commit");

        SimpleGroup callerPrincipalGroup;
        SimpleGroup roleGroup;
        Collection<Role> roles;

        authorization.initialize(null);

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
        System.out.println("Abort");

        return true;
    }

    private void processOptions() {
        System.out.println("Processing options");

        // OPTION_AUTHENTICATION_PROVIDER_CLASS
        String optionAthenticationClass = (String) options.get(OPTION_AUTHENTICATION_PROVIDER_CLASS);

        if (optionAthenticationClass == null) {
            throw new AuthException("Option " + OPTION_AUTHENTICATION_PROVIDER_CLASS + " not found");
        }

        try {
            Class<IAuthenticationProvider> clazz = (Class<IAuthenticationProvider>) Class.forName(optionAthenticationClass);
            authentication = clazz.newInstance();
        } catch (Exception e) {
            throw new AuthException("Invalid value of option " + OPTION_AUTHENTICATION_PROVIDER_CLASS, e);
        }

        // OPTION_AUTHORIZATION_PROVIDER_CLASS
        String optionAthorizationClass = (String) options.get(OPTION_AUTHORIZATION_PROVIDER_CLASS);

        if (optionAthorizationClass == null) {
            throw new AuthException("Option " + OPTION_AUTHORIZATION_PROVIDER_CLASS + " not found");
        }

        try {
            Class<IAuthorizationProvider> clazz = (Class<IAuthorizationProvider>) Class.forName(optionAthorizationClass);
            authorization = clazz.newInstance();
        } catch (Exception e) {
            throw new AuthException("Invalid value of option " + OPTION_AUTHORIZATION_PROVIDER_CLASS, e);
        }

        //OPTION_THROWABLE_HANDLER_CLASS
        String optionThrowableHandlerClass = (String) options.get(OPTION_THROWABLE_HANDLER_CLASS);

        if (optionThrowableHandlerClass == null) {
            throw new AuthException("Option " + OPTION_THROWABLE_HANDLER_CLASS + " not found");
        }

        if (optionThrowableHandlerClass != null) {
            try {
                Class<IThrowableHandler> clazz = (Class<IThrowableHandler>) Class.forName(optionThrowableHandlerClass);
                throwableHandler = clazz.newInstance();
            } catch (Exception e) {
                throw new AuthException("Invalid value of option " + OPTION_THROWABLE_HANDLER_CLASS, e);
            }
        }
    }
}
