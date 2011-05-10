package org.jboss.seam.security.examples.id_provider;

import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.Model;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.saml.api.SamlIdentityProviderConfigurationApi;
import org.jboss.seam.security.external.saml.idp.SamlExternalServiceProvider;

@Model
public class SessionManagement {
    @Inject
    private SamlIdentityProviderApi idpApi;

    @Inject
    private SamlIdentityProviderConfigurationApi idpConfApi;

    public List<String> getNonParticipatingServiceProviders() {
        List<String> serviceProviders = new LinkedList<String>();
        for (SamlExternalServiceProvider sp : idpConfApi.getServiceProviders()) {
            if (!isSessionParticipant(sp)) {
                serviceProviders.add(sp.getEntityId());
            }
        }
        return serviceProviders;
    }

    public List<String> getParticipatingServiceProviders() {
        List<String> serviceProviders = new LinkedList<String>();
        for (SamlExternalServiceProvider sp : idpConfApi.getServiceProviders()) {
            if (isSessionParticipant(sp)) {
                serviceProviders.add(sp.getEntityId());
            }
        }
        return serviceProviders;
    }

    private boolean isSessionParticipant(SamlExternalServiceProvider sp) {
        return idpApi.getSession().getServiceProviders().contains(sp);
    }

    public void samlRemoteLogin(String spEntityId) {
        if (idpApi.getSession() == null) {
            throw new RuntimeException("No local SAML session.");
        }
        idpApi.remoteLogin(spEntityId, null, (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
    }
}
