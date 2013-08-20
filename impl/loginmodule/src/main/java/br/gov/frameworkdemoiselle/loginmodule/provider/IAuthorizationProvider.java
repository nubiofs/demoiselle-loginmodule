package br.gov.frameworkdemoiselle.loginmodule.provider;

import java.security.Principal;
import java.util.Collection;
import java.util.Properties;

import javax.security.auth.login.LoginException;

import br.gov.frameworkdemoiselle.loginmodule.Role;

/**
 * <p>Implementations of this interface are used to {@link ProviderLoginModule}
 * realize authorization.</p>
 *
 * @author CETEC/CTJEE
 */
public interface IAuthorizationProvider {

    /**
     * Initialize provider with properties load from {@link ProviderLoginModule}
     *
     * @param properties configuration properties
     */
    public void initialize(Properties properties);

    /**
     * Authorize caller principal
     *
     * @param callerPrincipal Principal returned from the authorization
     * @return Collection of roles authorized
     */
    public Collection<Role> authorize(Principal callerPrincipal) throws LoginException;
}
