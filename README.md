FastCGI Proxy Server
=====================

facebook libphenom + fastcgi_client + php-fpm

Install
--------
Modify Makfile for your env, and then just `make`

Or You can use CMake:

`mkdir build`

`cd buiild`

`cmake .. -DLIBPHENOM_PATH=/home/ideal/local/libphenom`

Reference
---------


Nginx fastcgi module
---------------------

- Supports only a single request per connection (no request multiplexing).
- Only FCGI_RESPONDER role is supported.
