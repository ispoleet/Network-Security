### Purdue CS528 - Network Security - Spring 2016
### Lab 3: Virtual Private Network
___ 
 
### Introduction
In this lab we implemented a simple VPN service. The purpose of VPN is to provide a client a "virtual" connection to a different network. Although client may not be physically connected to that network, he can have exactly the same functionality as being physically connected to it. This can be done by "grapping" all IP packets, send them to a remote host that is on the target network, and forward them in the target network. 

More specifically it works as follows: Client creates a TUN/TAP (TUN in our case) tunnel interface and configures properly the routing tables. The tunnel has an IP address. When a packet need to be send to that address, the TUN/TAP driver steal the packet and instead of routing it as a normal packet it forward it to user mode process (TUN interface forwards the whole IP packet, while TAP forwards the whole Ethernet packet). Then the user mode process gets this IP packet, encapsulates it and sends it over UDP to remote host that is physically on that network. The remote host receives the packet, extract the IP packet and forwards it to the network.

The obvious problem with that is that there's no encryption. An eavesdropper can see all tunneled packets. For this reason we need to encrypt all the packets in a safe manner to provide both confidentiality and integrity. Let's see how we can achieve these properties and how miniVPN is implemented.

___
### Implementation Details
miniVPN is a simple VPN server-client program. It provides an encrypted tunnel of IP packets over UDP. It works as follows: First a tunnel interface is created at both ends and the routing tables are configured properly. Then an SSL connection is established between server and  client. Using this encrypted connection session keys and IVs are negotiated. Once the crypto parameters configured, we start forwarding packets between tunnel interfaces in both ends.

Each packet is encrypted using AES128 CTR and encapsulated in a UDP payload. Thus we can ensure confidentiality of the packet. Integrity is also provided by using HMAC of the encrypted packet (SHA 256 is used); Encrypt then MAC mode.

When connection established, both sides exchange an 48byte random nonce, and the session key is calculated as follows: sess_key = md5(client_nonce || server_nonce). The goal of the session key is to be unpredictable, so the randomness of the nonces can ensure this property. Using the counter mode, we exchange IVs through the SSL channel, and thus we don't have to send them within each packet.

Note that it's possible for some reason IVs to stop being synchronized, if for example packets arrive out of order. In that keys we have inform other peer and reset a new IV. We can easily detect unsynced IVs by placing a signature at the beginning of each packet. If decryption fails we can infer that IVs are not sync. This is because HMAC can provide ciphertext integrity, so the only reason that decryption will fail is due to the bad IVs. Note that with this design we can detect replay attacks. Packets with invalid MAC are dropped. Client can negotiate a new session key or set a new IV at any time and inform server about this change.

Client is authenticated using public keys. If public keys are not available on the client side, we fall-back in username/password authentication. Server request and authentication and client responds with a username and a password. Server verifies them by looking up its shadow file and either allows clients to connect or terminates connection.

Control protocol runs over SSL channel. The UDP channel is used only for exchanging encrypted data. Client starts with a HELO message, and server responds with a HELO ACK. If client hasn't public keys, server sends an AUTH REQ message and server responds with a USR AUTH message which contains username and password. Server verifies the credentials and sends back either an AUTH SUCC or an AUTH FAIL message.

Once client gets authenticated, both sides send a NONCE and an IV message, and negotiate a session key. During runtime, client can send a NONCE or an IV message and set a new IV or a session key.

When client wants to terminate connection, a TUN FIN message is send, so the server can release allocated resources.

___
### Running the tunnel

Running the code is pretty straight forward. The same program can be used both as a server or as a client. The command line arguments are shown below: 
```
    -S	operate as a VPN server
    -C <server_ip>	operate as a VPN client
    -p <port>	port to connect or listen (depends on -S|-C)
    -a <*.crt>	CA certificate file name
    -c <*.crt>	host's certificate file name
    -k <key>	host's private key file name
    -U	use Username/Password authentication
    -i <dev>		TUN interface device name
    -l <iface_ip>	IP address of TUN interface
    -m <iface_mask>	subnet mask of TUN interface
    -r <net_ip>		remote virtual network address
    -n <net_mask>	remote virtual network subnet mask
    -x	do not use tunnel encryption
    -d	enable debug mode - display verbose information
    -h	print help message and exit
```

Beyond that, there are some runtime commands that supported by our program. We can enter such a command by pressing Ctrl+C (^C). Here are the available runtime commands:
```
    SETKEY 	    Set a new nonce and update the session key
    SETIV		Set a new IV and inform the other side
    CLOSE  	    Close this command window
    KILL 		Kill current process (SERVER only) - Do not inform other side
    EXIT   	    Terminate VPN peer (CLIENT only)
    HELP   		Print help message
```

Let's see some examples:
*	Setup a VPN server at port 9999, using CA certificate 'ca.crt', server certificate 'server.crt' and private key 'server.key'. Tunnel interface is 'tun0' with IP 10.0.1.1/24. Remote network is 10.0.2.0/24. Enable debug mode.
```
	sudo ./minivpn -S -p9999 -a ca.crt -c server.crt -k server.key 
		-i tun0 -l 10.0.1.1 -m 255.255.255.0 -r 10.0.2.0 -n 255.255.255.0 -d
```

*	Connect to VPN server 192.168.1.100:9999 using public key authentication. Tunnel interface is 'tun0' with IP 10.0.2.1/24. Remote network is 10.0.1.0/24. Enable debug mode too.
```
	sudo ./minivpn -C 192.168.1.100 -p9999 -a ca.crt -c client.crt -k client.key 
		-i tun0 -l 10.0.2.1 -m 255.255.255.0 -r 10.0.1.0 -n 255.255.255.0 -d
```
*	Connect to VPN server 192.168.1.100:9999 using username/password authentication. Tunnel interface is 'tun0' with IP 10.0.2.1/24. Remote network is 10.0.1.0/24. Enable debug mode too.
```
	sudo ./minivpn -C 192.168.1.100 -p9999 -a ca.crt -U
		-i tun0 -l 10.0.2.1 -m 255.255.255.0 -r 10.0.1.0 -n 255.255.255.0 -d
```
___


### Runtime Examples

Let's start with the simple tunnel; no encryption is provided (we use -x argument). In order to be able to understand what's going on we'll use a very simple protocol. We'll bind a local TCP server at port 8888 at one side and we'll connect to it using our tunnel from the other side. Figure 1 (top) shows the data going back and forth to the tunnel interface. Figure 1 (bottom) shows the actual data that are transmitted. Note that although we send 1 TCP packet (the word "KYRIAKOS"), more packets are sent. This is because we use TCP, so ACK packets must be sent too.

![alt text](./images/image_1.png 
"Figure 1. Sending unencrypted data over tunnel ")
 
Figure 2 takes a closer look at the UDP packets that arrive in the remote host:

![alt text](./images/image_2.png 
"Figure 2. A UDP packet that carries an IP packet as a payload")

The payload of this UDP packet, is an IP packet. The payload of this IP packet is a TCP packet which contain the word "KYRIAKOS". Now it's clear how tunnel works. The remote hosts receives the UDP packet, extracts the IP packet and forwards it to the network. Thus the network will "believe" that this IP packet come from a host that is physically connected there.

The transmission of the packets as plaintext can be a problem here. In figure 2 we are able to see what tunneled packets contain. 

In figure 3 we used encryption. Although there's no difference from figure 1, we can see the difference at the packet level in figure 4. The packet is encrypted so an eavesdropper can't see anything.

![alt text](./images/image_3.png 
"Figure 3. Sending encrypted data over tunnel")


![alt text](./images/image_4.png 
"Figure 4.A UDP packet that carries and encrypted IP packet as a payload")

___

### Additional Features

Let's stay on the example at figures 3 and 4, and assume that we want to change the session key (changing the IV is similar, so we won't discuss it here). All we have to do is press Ctrl+C (in client side) and enter the runtime command "SETKEY" as shown below:

![alt text](./images/image_5.png 
"Figure 5. Changing the session key (Client side)")

We can see here that we set a new nonce and we inform the other side about this change ("49 bytes sent to SSL channel"). After that we got a message that a new shared key is negotiated ("896EFD..."). Once we do that we can continue sending and receiving data over the tunnel without any problem. Our connection remains open and we can send new data (the word "ISPO"). Figure 6 shows what's going on the server during session key update.

We can see here that server received control command 66 (NONCE) so he updated the client's nonce and recalculated the new session key. Note that (obviously) the session key is the same in both sides.

![alt text](./images/image_6.png 
"Figure 6. Changing the session key (Server side)")


The final example is what happens when client does not have public keys for the authentication. In that we must authenticate the client using a different method. The most common is the username/password approach. In order for a client to have a successful authentication, he should provided a valid username and a password combination that exist in the shadow file of the host that server runs. In other words, if a client has a local account on the machine that server runs, he can grant access to the VPN service. We can access user authentication by using the flag -U when we start the client.

Figure 7 shows a failed attempt to login. Username/password combination is wrong, so the server terminates the connection.

![alt text](./images/image_7.png 
"Figure 7. A failed user authentication")
 
However, if authentication is successful, client can gain access to the VPN as shown in figure 8. Beyond that we see in that screenshot how the protocol works and how the session key and the IVs are negotiated.

![alt text](./images/image_8.png 
"Figure 8. A successful user authentication")
___
