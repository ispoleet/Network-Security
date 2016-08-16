### Purdue CS528 - Network Security - Spring 2016
### Lab 1: Sniffing and Spoofing
___

### Spoofing

We can spoof a ping packet this way:
```
./spoof --payload='A bogus payload :)' --type=ping  --dst-ip=192.168.15.5  
    --src-ip=99.99.99.99
```

In this example we send an ICMP echo request packet with a bogus payload to 192.168.15.5 with 
source address 99.99.99.99. At the same time we launch tcpdump on 192.168.15.5 to sniff the 
spoofed packet:

![alt text](./images/image_1.png 
"Figure 1. Sending spoofed ping requests")
 

Sending a spoofed Ethernet frame is simple too:
```
./spoof --payload='A dummy frame! ' --type=ethernet --dst-mac=08:00:27:1c:7b:03 
    --src-mac=01:02:03:04:05:06 
```
In this case (figure 2) we send a frame to 08:00:27:1c:7b:03 (VM2) with source MAC address
 01:02:03:04:05:06. However this frame is totally useless -and also has invalid an IP header. 
 It's possible to send a spoofed Ethernet frame with a useful ICMP echo request payload (figure 3):
```
./spoof --payload='A wonderful example of encapsulation!' --type=all 
    --src-ip=99.99.99.99 --dst-ip=192.168.15.5  --dst-mac=08:00:27:1c:7b:03 
    --src-mac=01:02:03:04:05:06  
```

![alt text](./images/image_2.png 
"Figure 2. Sending spoofed Ethernet frames")
 
![alt text](./images/image_3.png 
"Figure 3. Sending spoofed Ethernet frames, with spoofed ICMP payloads")
 
___

### Sniffing and Spoofing

For this task we need functionality from both sniffex and spoof.c. Thus we created a program 
(sniff_n_spoof.c) which reuses much of the code from both files. Figure 9 shows the results.
When we do a ping to 8.8.8.8 (Google's public DNS) we don't get any response (time 11:36). But when we enable our sniff_n_spoof program (at 11:37)  we can see that ping to 8.8.8.8 works without any losses. Note that this only works for 8.8.8.8; As you can see in figure 10, sniff and spoofing doesn't work for any other address like 9.9.9.9.

We have to be careful here. If we send a spoofed IP packet, is not enough. We have to send a spoofed Ethernet frame, otherwise MAC address won't be consistent, and thus packet will be dropped by destination.

![alt text](./images/image_4.png 
"Figure 4. Sniffing and spoofing")
 
 ![alt text](./images/image_5.png 
"Figure 5. Spoofing doesn't work with different IP addresses")
 
___
