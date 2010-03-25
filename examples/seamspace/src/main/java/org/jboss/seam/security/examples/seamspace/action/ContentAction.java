package org.jboss.seam.security.examples.seamspace.action;

import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.examples.seamspace.model.MemberImage;

@Named
public class ContentAction
{
   @Inject EntityManager entityManager;
   @Inject Identity identity;
   
   public MemberImage getImage(int imageId)
   {
      MemberImage img = entityManager.find(MemberImage.class, imageId);
      
      if (img == null || !identity.hasPermission(img, "view"))
         return null;
      else
         return img;
   }
}
