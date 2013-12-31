<?php
error_reporting(E_ALL);
set_time_limit(0);

echo "TCP/IP Connection ... ";

$ip = "127.0.0.1";
$port = 8080;
 
/*
  +-------------------------------
  *    @socket连接整个过程
  +-------------------------------
  *    @socket_create
  *    @socket_connect
  *    @socket_write
  *    @socket_read
  *    @socket_close
  +--------------------------------
*/
 
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

if ($socket < 0) {
    echo "socket_create() failed: reason: " . socket_strerror($socket) . "\n";
}else {
    echo "OK.\n";
}
 
echo "Try to connect to host '$ip' port '$port'... ";

$result = socket_connect($socket, $ip, $port);
if ($result < 0) {
    echo "socket_connect() failed.\nReason: ($result) " . socket_strerror($result) . "\n";
}else {
    echo "OK.\n";
}
 
$in = "way=get\r\n";

$out = '';
 
if(!socket_write($socket, $in, strlen($in))) {
    echo "socket_write() failed: reason: " . socket_strerror($socket) . "\n";
}else {
    echo "Send Ok!\n";
    echo "Send content: $in \n";
}

$out = socket_read($socket, 8192);
echo "Receive Ok! \n";
echo "Receive content:\n\n", $out . "\n\n";
 
echo "Close socket... ";
socket_close($socket);
echo "OK.\n\n";

