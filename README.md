##VPN - project
Creating a secured communication channel between client and server. The client and server exchange certificates signed by a common CA, validate each others and agree on session parameters which are encrypted using public key encryption through the handshake.

Once the connection is set up, a connection can be made to the vpn-client and the vpn-server so data can be transformed securely.

![vpn netwrok ](https://github.com/5habeeb/VPN-Project/blob/master/vpn.png)

###Run the program
Run the forwardServer:
```
$ java ForwardServer --handshakeport=2206 --usercert=server.pem--cacert=ca.pem --key=server-private.der
```
   
Run the forwardServer:
```
$ java ForwardClient --handshakehost=<host>  --handshakeport=2206 --targethost=<host> --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der
```

###Test the Program
Netcat can be used to test the program.

##On Windows
1. Download [netcat](https://eternallybored.org/misc/netcat/)
2. Open command prompt and cd to netcat path, then
 
Create a test server
```
$ nc.exe -vv -l -p XXXX
```
- Create a test client
```
$ nc.exe -vv <host> -p XXXX
```

##On Mac and Linux
Create a test server
```
$ nc -l XXXX
```
- Create a test client
```
$ nc <host> XXXX
```