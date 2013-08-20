package br.gov.frameworkdemoiselle.loginmodule.provider;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.security.auth.login.LoginException;

/**
 * <p>Implementations of this interface are used to {@link ProviderLoginModule}
 * realize authentication.</p>
 *
 * @author CETEC/CTJEE
 */
public interface IAuthenticationProvider {

    /**
     * Initialize provider with properties load from {@link ProviderLoginModule}
     *
     * @param properties configuration properties
     */
    public void initialize(Properties properties);

    /**
     * Authenticate with username and password
     *
     * @param user username
     * @param password password
     * @return Principal authenticated or null if the authentication fails
     */
    public Principal authenticate(String user, String password) throws LoginException;

    /**
     * Authenticate with username, password and new password
     *
     * @param user username
     * @param password password
     * @param newPassword new password
     * @return Principal authenticated or null if the authentication fails
     */
    public Principal authenticate(String user, String password, String newPassword) throws LoginException;

    /**
     * Authenticate with certificate
     *
     * @param x509 certificate
     * @return Principal authenticated or null if the authentication fails
     */
    public Principal authenticate(X509Certificate x509) throws LoginException;
}
