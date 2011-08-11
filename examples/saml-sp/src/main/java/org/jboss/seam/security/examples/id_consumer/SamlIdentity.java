package org.jboss.seam.security.examples.id_consumer;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

@Model
public class SamlIdentity {
    @Inject
    private SamlServiceProviderApi samlSpApi;

    @Dialogued
    public void login(String idpEntityId) {
        if (!isLoggedIn()) {
            samlSpApi.login(idpEntityId, (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
        } else {
            FacesMessage facesMessage = new FacesMessage("Already logged in.");
            FacesContext.getCurrentInstance().addMessage(null, facesMessage);
        }
    }

    public void localLogout() {
        if (isLoggedIn()) {
            if (samlSpApi.getSession() != null) {
                samlSpApi.localLogout();
            }
        } else {
            FacesMessage facesMessage = new FacesMessage("Not logged in.");
            FacesContext.getCurrentInstance().addMessage(null, facesMessage);
        }
    }

    public void globalLogout() {
        if (isLoggedIn()) {
            if (samlSpApi.getSession() != null) {
                samlSpApi.globalLogout((HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
            }
        } else {
            FacesMessage facesMessage = new FacesMessage("Not logged in.");
            FacesContext.getCurrentInstance().addMessage(null, facesMessage);
        }
    }

    public boolean isLoggedIn() {
        return samlSpApi.getSession() != null;
    }

    public SamlSpSession getSamlSpSession() {
        return samlSpApi.getSession();
    }

    public void redirectToLoginIfNotLoggedIn() {
        if (!isLoggedIn()) {
            redirectToViewId("/Login.xhtml");
        }
    }

    private void redirectToViewId(String viewId) {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        FacesContext.getCurrentInstance().getApplication().getNavigationHandler().handleNavigation(facesContext, null, viewId + "?faces-redirect=true");
    }
}
