Seam Security Examples
======================

Running the functional tests
- start JBoss Application Server 6 or higher
- deploy the example
- in the example folder, run mvn verify -Pftest


Running a functional test for openid-rp example
===============================================

In addition to the steps above you first need to do the following:

Map this host name to the localhost:

www.openid-rp.com

On Unix based systems, you do this by putting the following lines in
'/etc/hosts':

127.0.0.1   www.openid-rp.com

Furthermore, add credentials for particular accounts (MyOpenID, Google, Yahoo) to:

openid-rp/src/test/resources/ftest.properties 
