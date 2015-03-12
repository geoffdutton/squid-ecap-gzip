# Installation #

## 1. Download and install libecap Library ##

  * Download and unpack latest libecap library from: http://www.e-cap.org/Downloads (or use [local mirror of version 0.0.3](http://squid-ecap-gzip.googlecode.com/files/libecap-0.0.3.tar.gz))
```
wget http://www.measurement-factory.com/tmp/ecap/libecap-0.0.3.tar.gz
tar xvfz libecap-0.0.3.tar.gz
```

  * Build and install libecap library:
```
cd libecap-0.0.3/
./configure
make
make install
```


## 2. Download and install VIGOS eCAP GZIP Adapter ##

  * Download and unpack latest VIGOS eCAP GZIP adapter from here
```
wget http://squid-ecap-gzip.googlecode.com/files/squid-ecap-gzip-1.3.0.tar.gz
tar xvfz squid-ecap-gzip-1.3.0.tar.gz
```
  * Build and install VIGOS eCAP GZIP adapter:
```
cd squid-ecap-gzip/
./configure
make
make install
```

## 3. Download and install SQUID proxy cache, version 3.1+ ##

**Important:**
The eCAP feature is only available in SQUID version 3.1 or higher. You cannot use the VIGOS eCAP GZIP adapter with earlier versions of SQUID (e.g. 2.6, 2.7, 3.0).

  * Download and unpack latest SQUID version from http://www.squid-cache.org/Versions/v3/3.1/
```
wget http://www.squid-cache.org/Versions/v3/3.1/squid-3.1.11.tar.gz
tar xvfz squid-3.1.11.tar.gz
```
  * Configure, build and install SQUID:
```
cd squid-3.1.11/
./configure --enable-ecap
make
make install
```

## 4. Configure SQUID to use VIGOS eCAP GZIP Adapter ##

Add or edit the following lines in your etc/squid.conf:

```
ecap_enable on
ecap_service gzip_service respmod_precache 0 ecap://www.vigos.com/ecap_gzip
loadable_modules /usr/local/lib/ecap_adapter_gzip.so
acl GZIP_HTTP_STATUS http_status 200
adaptation_access gzip_service allow GZIP_HTTP_STATUS
```

Now, after (re-)starting SQUID, all `text/html` responses from clients sending the `Accept-encoding: gzip` HTTP header will be compressed.