FastCGI Proxy Server
=====================

facebook libphenom + fastcgi_client + php-fpm

Install
--------
Modify Makfile for your env, and then just `make`

Reference
---------


Nginx fastcgi module
---------------------

- Supports only a single request per connection (no request multiplexing).
- Only FCGI_RESPONDER role is supported.
