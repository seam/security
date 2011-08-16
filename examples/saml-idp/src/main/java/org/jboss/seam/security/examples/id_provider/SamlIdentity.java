package org.jboss.seam.security.examples.id_provider;

import java.io.Serializable;

import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;

@Named
public class SamlIdentity implements Serializable {
    private static final long serialVersionUID = 3739296115750412807L;

    @Inject
    private SamlIdentityProviderApi samlIdp;

    public void localLogin(String userName) {
        samlIdp.localLogin(samlIdp.createNameId(userName, null, null), null);
    }

    public void remoteLogin(String spEntityId) {
        samlIdp.remoteLogin(spEntityId, null, (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
    }

    public void localLogout() {
        samlIdp.localLogout();
    }

    public void globalLogout() {
        samlIdp.globalLogout((HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
    }

    public boolean isLoggedIn() {
        return samlIdp.getSession() != null;
    }

    public void redirectToLoginIfNotLoggedIn() {
        if (!isLoggedIn()) {
            redirectToViewId("/Login.xhtml");
        }
    }

    public SamlIdpSession getSamlIdpSession() {
        return samlIdp.getSession();
    }

    private void redirectToViewId(String viewId) {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        FacesContext.getCurrentInstance().getApplication().getNavigationHandler().handleNavigation(facesContext, null, viewId + "?faces-redirect=true");
    }
}
