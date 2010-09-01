SAML-IDP EXAMPLE


What is it? 
===========

This demo web application shows how to turn your application into a SAMLv2
identity provider (IDP). It makes use of the SAMLv2 submodule of Seam Security.


How to deploy it? 
=================

The application is packaged as a war file and should run in any JEE6
environment. It has been tested on JBoss AS 6. Before deploying the application,
you need to map this two host name to the localhost:

www.saml-idp.com

On Unix based systems, you do this by putting the following lines in
'/etc/hosts':

127.0.0.1	www.saml-idp.com


Some background info
====================

The Identity Provider is preconfigured to run at port 8080, to use a test key
store which is included in the war file, and to use the http protocol for
communicating with IDPs. These settings are ok for a test setup, but please be
aware that in production, you'd use http on port 443, and you'd use your own
well-secured keystore, probably somewhere on the file system. In the test
application these settings are done programmatically (by the IdpCustomizer).


How to use the application
==========================

Start the application and surf to:

http://www.saml-idp.com:8080/saml-idp

First you need to configure the service provider(s) to trust. You have different
options:
- use the seam-sp example application
- install and use your own SAMLv2 compliant service provider
- use an existing SAMLv2 service provider where you have access to (e.g. Google
Applications Premium edition, which can act as a SAMLv2 Service Provider)

You need to create a trust relationship between the chosen service provider(s)
and the sample application. You do that by exchanging meta data. The menu option
"Configuration" will help you. Note that in a production system you'd definitely
restrict such a configuration page to system administrators! On the
configuration page, you see a link that points out where the meta data of the
current identity provider resides. You use that link for uploading the meta data
to your service provider. The other way around, you find out where your service
provider's meta data is (read your SP manual), and you upload it on the
Configuration page. Repeat this procedure for all service providers.

Now you are ready to login. Go to the login page by using the menu, and supply
your user name. A real life app will ask for your password to verify your
identity, but for this example we just assume it's ok. When logged in, you can
access the session management page. There you see the name of the current user,
and the service provider sessions that are active. No service provider session
is active at this moment. You can now try to login to your service provider, and
see that you don't have to sign in again, cause you're already logged in at the
identity provider. You can also login to a service provider from the session
management page. This option will open the service provider's application in a
new window, and you'll be logged in there immediately.

After having experienced single sign on, you can play around with logout
scenarios. A global logout will log you out the session at the IDP and all
participating sessions at the SPs. A local logout at the IDP will remove the IDP
session without informing the service providers that participate in the session.