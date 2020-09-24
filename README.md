# Code injector

**DISCLAIMER**

All content posted on the repository is for educational and research purposes only. Do not attempt to 
violate the law with anything contained here. Administrators of this server, the authors of this material, 
or anyone else affiliated in any way, are not going to accept responsibility for your actions. Neither 
the creator nor GitHub is not responsible for the comments posted on this repository.

This site contains materials that can be potentially damaging or dangerous. 
If you do not fully understand please LEAVE THIS WEBSITE. Also, be sure to check laws 
in your province/country before accessing repository.

Note: In order to be a man-in-the-middle, you need to execute the ARP spoof script

code_injector.py sniff data that flows from the victim to websites. Websites response to the hacker machine
and the hacker changes the page, ex. pastes malicious script.

As you may guess, we need to insert an iptables rule, open the linux terminal and type:

```
iptables -I FORWARD -j NFQUEUE --queue-num 0
```

Moreover, it is important to change HTTTP/1.1 to HTTP/1.0 in order to sey websever that we can not 
accept page as a several packages, because it is easies to change only one package response.

Besides, it is important to send to the server "Accept-Encoding:.*?". It means that we can not precess encoding.

Additionally, it is important to replace "Content-Length", because if we add data to the page, 
the content length will change. Therefore, the page will not display correctly.

```
sub(b"Accept-Encoding:.*?\\r\\n", b"", load)
load.replace(b"HTTP/1.1", b"HTTP/1.0")
search("(?:Content-Length:\s)(\d*)", str(load))
```