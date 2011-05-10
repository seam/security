package org.jboss.seam.security.examples.id_consumer;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderConfigurationApi;

@Model
public class Configuration {
    private String idpMetaDataUrl;

    @Inject
    private SamlServiceProviderConfigurationApi spConfigApi;

    public String getIdpMetaDataUrl() {
        return idpMetaDataUrl;
    }

    public void setIdpMetaDataUrl(String idpMetaDataUrl) {
        this.idpMetaDataUrl = idpMetaDataUrl;
    }

    public void addSamlIdentityProvider() {
        try {
            URL url = new URL(idpMetaDataUrl);
            URLConnection urlConnection = url.openConnection();
            urlConnection.setConnectTimeout(3000);
            urlConnection.setReadTimeout(3000);
            Reader reader = new InputStreamReader(urlConnection.getInputStream());
            SamlExternalEntity samlEntity = spConfigApi.addExternalSamlEntity(reader);

            FacesMessage facesMessage = new FacesMessage("SAML entity " + samlEntity.getEntityId() + " has been added.");
            FacesContext.getCurrentInstance().addMessage(null, facesMessage);
        } catch (MalformedURLException e) {
            FacesMessage facesMessage = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Malformed URL.", "");
            FacesContext.getCurrentInstance().addMessage(null, facesMessage);
        } catch (IOException e) {
            FacesMessage facesMessage = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Metadata could not be read.", "");
            FacesContext.getCurrentInstance().addMessage(null, facesMessage);
        }
    }

    public String getMetaDataUrl() {
        return spConfigApi.getMetaDataURL();
    }

    public List<String> getIdpEntityIds() {
        List<String> entityIds = new LinkedList<String>();
        for (SamlExternalEntity entity : spConfigApi.getExternalSamlEntities()) {
            entityIds.add(entity.getEntityId());
        }
        return entityIds;
    }
}
