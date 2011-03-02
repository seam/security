package org.jboss.seam.security.externaltest.integration.client;

import org.jboss.arquillian.spi.ClassContextAppender;
import org.jboss.arquillian.spi.Context;
import org.jboss.arquillian.spi.event.container.AfterDeploy;
import org.jboss.arquillian.spi.event.container.BeforeUnDeploy;

public class ClassContextAppenderImpl implements ClassContextAppender
{
   public void append(Context context)
   {
      context.register(AfterDeploy.class, new AfterDeployEventHandler());
      context.register(BeforeUnDeploy.class, new BeforeUnDeployEventHandler());
   }
}
