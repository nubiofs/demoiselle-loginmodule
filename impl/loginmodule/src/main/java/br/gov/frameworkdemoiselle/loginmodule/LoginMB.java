package br.gov.frameworkdemoiselle.loginmodule;

import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.gov.frameworkdemoiselle.loginmodule.message.implementation.RequestThrowableHandler;
import br.gov.frameworkdemoiselle.loginmodule.provider.ProviderLoginModule;

public class LoginMB {

    private String username;
    private String password;
    private String newPassword;
    private String successPageRedirect;
    private String errorPageRedirect;
    private static final String CERTIFICATES_ATTR = "javax.servlet.request.X509Certificate";

    private Logger logger;
    
    public LoginMB() {
		logger = LoggerFactory.getLogger(LoginMB.class);
		logger.info("Iniciando o LoginMB");
	}
    
    public void onPageLoad() {
    	logger.info("Direcionando para autenticacao com certificado digital");

        authenticateClientCertificate();
    }

    public String autenticateUsernamePassword() {
    	logger.info("autenticateUsernamePassword");

        HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();

        request.setAttribute(ProviderLoginModule.USERNAME, username);
        request.setAttribute(ProviderLoginModule.PASSWORD, password);
        request.setAttribute(ProviderLoginModule.NEW_PASSWORD, newPassword);

        FacesMessage message;

        try {
            request.login(ProviderLoginModule.USER_PASSWORD, null);

            return successPageRedirect;
        } catch (ServletException e) {
            e.printStackTrace();

            if (request.getAttribute(RequestThrowableHandler.THROWABLE_KEY) != null) {
                return errorPageRedirect;
            } else {
                message = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Falha no processamento do login. Consulte a equipe de suporte do sistema.", null);

                FacesContext.getCurrentInstance().addMessage(null, message);

                return errorPageRedirect;
            }
        }
    }

    public void authenticateClientCertificate() {
    	logger.info("authenticateClientCertificate");
        FacesContext context = FacesContext.getCurrentInstance();

        HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getRequest();

        X509Certificate certs[] = (X509Certificate[]) request.getAttribute(CERTIFICATES_ATTR);

        FacesMessage message;

        if (certs != null) {
            request.setAttribute(ProviderLoginModule.X509, certs[0]);

            try {
                request.login(ProviderLoginModule.CLIENT_CERTIFICATE, null);
                
                logger.info("Login efetuado com sucesso, redirecionando para: " + successPageRedirect);
                
                context.getApplication().getNavigationHandler().handleNavigation(context, null, successPageRedirect);
            } catch (ServletException e) {
                e.printStackTrace();

                if (request.getAttribute(RequestThrowableHandler.THROWABLE_KEY) != null) {
                    context.getApplication().getNavigationHandler().handleNavigation(context, null, errorPageRedirect);
                } else {
                    message = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Falha no processamento do login. Consulte a equipe de suporte do sistema.", null);

                    FacesContext.getCurrentInstance().addMessage(null, message);

                    context.getApplication().getNavigationHandler().handleNavigation(context, null, errorPageRedirect);
                }
            }
        } else {
            message = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Não foi possível acessar o certificado do usuário.", null);

            FacesContext.getCurrentInstance().addMessage(null, message);

            context.getApplication().getNavigationHandler().handleNavigation(context, null, errorPageRedirect);
        }
    }

    public String logout() {
    	logger.info("logout");

        HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();

        FacesMessage message;

        try {
            request.logout();
        } catch (ServletException e) {
            e.printStackTrace();

            message = new FacesMessage(FacesMessage.SEVERITY_ERROR, "O logout falhou.", "Falha no processamento do logout. Consulte a equipe de suporte do sistema.");

            FacesContext.getCurrentInstance().addMessage(null, message);

            return errorPageRedirect;
        }

        return successPageRedirect;
    }

    public String getUserPrincipalName() {
    	logger.info("getUserPrincipalName");

        HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();

        Principal principal = request.getUserPrincipal();

        if (principal != null) {
            return principal.getName();
        } else {
            return null;
        }
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getSuccessPageRedirect() {
        return successPageRedirect;
    }

    public void setSuccessPageRedirect(String successPageRedirect) {
        this.successPageRedirect = successPageRedirect;
    }

    public String getErrorPageRedirect() {
        return errorPageRedirect;
    }

    public void setErrorPageRedirect(String errorPageRedirect) {
        this.errorPageRedirect = errorPageRedirect;
    }
}
