### Purdue CS528 - Network Security - Spring 2016
### Lab 2: Remote DNS Cache Poisoning
___



### Introduction
In this project we implemented a remote DNS cache poisoning attack. The goal of this attack is to force a DNS resolver to save in its cache a IP for a given domain that is different from the original one. DNS cache poisoning attacks are the Swiss army knife for a hacker. Ôhere are many potential further attacks after a successful DNS cache poisoning. For example, after a successful cache poisoning, when a user asks the resolver for the address of www.google.com instead of 216.58.216.68, the resolver will return 9.9.9.9, which an IP controlled by an attacker. Once the user gets connected to the wrong machine, there are many attack avenues.

In order to increase the chances of making our attack successful, we're going to use Kaminsky's observation. Let R be the resolver that we want to poison its cache, let foo.gr be the domain that we want to poison and let F be the DNS server of foo.gr. We start by sending a DNS query for the subdomain r4nd0m.foo.gr to R. Because R don't have this random subdomain in its cache it send a DNS query to F trying to resolve that bogus subdomain. At this time, we flood R with spoofed DNS responses (source address = F). In these responses, we set address of r4nd0m.foo.gr to our desired address (let's say 9.9.9.9) but we also set the nameserver of foo.gr (9.9.9.9). If one of these responses has the same transaction ID with the original query, R will think that the spoofed response really comes from F, so it will store 9.9.9.9 as the nameserver of foo.gr. Otherwise we can try again with a different subdomain.

Once R receives a valid DNS response (either from us or from F), it will reply to us with  either a "No such name" response (attack failed) or a "r4nd0m.foo.gr is at 9.9.9.9" (cache poisoning was successful).

The chances of guessing the right transaction ID is 1/65536, which is not very good. However, if we send K parallel request and then send M spoofed responses, chances are much higher, because only 1 successful poisoning is enough. By exploiting the birthday paradox we only need any of M responses to match with any of the K requests, which makes our chances much higher (<< K*S/65536 though because many packets will be ignored).

___
### Implementation Details
The code consists of 3 parts. The first part is responsible for sending arbitrary packets, the 2nd is for creating arbitrary DNS packets, and the third part performs the actual attack.


#### Sending Arbitrary Packets

The first part of the code contains some functions for sending and receiving arbitrary packets:
•	snd_spfd_pkt(): Send an IP packet with spoofed source address and an arbitrary UDP payload.
•	snd_pkt(): Send an normal UDP packet.
•	rcv_pkt(): Receive a UDP packet.

#### Crafting Arbitrary DNS packets

This is the most tricky part. This is because DNS packets consist of many different fields of variable length. Because we need an easy way to create arbitrary DNS packet, we provided the following functions:

•	mk_dns_hdr(): Create and initialize a DNS packet header.
•	del_dns_pkt(): Delete a DNS packet.
•	app_q_rec(): Append a question record to an existing DNS packet.
•	app_r_rec(): Append a resource record to an existing DNS packet.

For example if want to send a DNS request, is as easy as follows:
	mk_dns_hdr(&D, 9999, DNS_FLAG_QUES, 1, 0, 0, 0);	
	app_q_rec(&D, IN, A, "foo.gr");

The 1st command, creates a DNS question packet with transaction ID 9999, which contains only 1 question. The 2nd command appends the actual query which is an address resolution for domain "foo.gr". Then variable D, contains the raw DNS packet, which now, it's ready to send.

#### Kaminsky Attack

By using the functions provided from the first 2 parts implementing the Kaminsky remote DNS cache poisoning attack becomes easy. First we create a random subdomain for the TLDN that we want to poison, and we do a DNS request for that domain. Because this random domain doesn't exists in the resolver's cache, the latter has to ask the original TLDN nameserver for that non existing subdomain. Under normal conditions, the nameserver will reply to our resolver with an error saying that this name doesn't exists.

Here comes our attack. At this point we flood the resolver with spoofed DNS responses which contain a bogus ip for that subdomain, and a poisoned nameserver for the top level domain name. However because we don't know the transaction ID we have to guess it. If our guess was successful, then our poisoning was successful.

An optional step here is to verify whether attack was successful by inspecting the DNS responses from the original queries that we did.

Obviously the chances of a successful attack here are 1/65536 (we have to guess the 2-byte random transaction ID). However if we do many parallel requests, it's possible to exploit the birthday paradox and increase our chances.

#### Question

Note that although it's possible to successfully poison the name server of our TLDN (nameserver of example.com is now ns.dnslabattacker.net) we can't provide an IP address for that nameserver (ns.dnslabattacker.net) in our spoofed response. If we try to include it as an additional RR, this may be ignored by if it uses the bailiwick rule. This just means that any records that aren't in the same domain of the question are ignored. So, if we ask for information about foo.example.com, then we only accept information in the additional section that is about example.com. Thus ns.dnslabattacker.net can't be answered in the additional section.

Thus we need another way to tell the resolver what's the ip address of ns.dnslabattacker.net. In our lab we simply store this ip address within resolver's name zone.

___
### Launching the attack

Launching the attack is very easy. All we have to do, is to set up the execute our program with the right parameters:
```
	./dns_cpoison --ip=192.168.15.4 --domain=example.com --orig-ns=199.43.132.53
  			  --attacker-ns=ns.dnslabattacker.net --attacker-ip=9.9.9.9 			        
              --n-requests=100 --n-responses=500 --n-tries=1000 --verify
```

The above command, does o a remote cache poisoning at Resolver 192.168.15.4. The domain that we want to poison is example.com and the IP of DNS server of example.com is 199.43.132.53. After poisoning, the nameserver of example.com will be ns.dnslabattacker.net at 9.9.9.9. We use 100 parallel requests and we flood with 500 spoofed responses. If attack is not successful, we repeat it for1000 times. After each attack, we verify if it was successful. With these numbers we need around ~1000 tries to successfully poison example.com.

___
### Evaluation
Below are the screen dumps from our evaluation. 
At figure 1, we can see that resolver's cache is successfully poisoned for the domain example.com:

![alt text](./images/image_1.png 
"Figure 1. A successfully cache poisoning attack for the domain example.com")
 
In figure 2 we can verify that our cache poisoning is successful, because the nameserver of example.com is now ns.dnslabattacker.net.

![alt text](./images/image_2.png 
"Figure 2. The nameserver of example.com is now poisoned.")
 
For the second task we want to verify that our attack was actually correct, by trying to resolve the domain example.com. Figures 3 and 4 show that this was true because the original IP address of www.example.com is 93.184.216.34 and not 1.1.1.1.

![alt text](./images/image_3.png 
"Figure 3. Resolving example.com after a successful DNS cache poisoning")


![alt text](./images/image_4.png 
"Figure 4. Resolving mail servers of example.com after a successful DNS cache poisoning")
 
___
