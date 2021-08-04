# MITM Proxy Server

## Overview

an mitm (men in the middle) proxy server that handle and intercept any tcp protocol comming from target device. <br/>
it can handle tls communication and normal tcp communication, analyze incoming data and catch target device running services APIs calls in real-time.<br/>

## Features

*   <b>DNS Spoofer</b> - fake dns to resolve 'A' records and simulate dns response to setup proxy server between target and service server communication.
*   <b>Certificate Authority</b> - fake CA to handle tls encrypted communication and generate trusted tls certificates.
*   <b>Proxy Server</b> - to intercept, log and forward data from target to service.

## Implementation

### DNS Spoofer

fake dns tool built using `Scapy` module to listen/sniff for dns request comming from target device and simulate dns responses on port 53.<br/>
using `PyDNS` module dns can resolve A records for incomming requests.<br/>
<br/>

### Certificate Authority

fake CA tool built using `PyOpenSSL` module, can generate '.pem' certificate files and generate a root CA public/private key pair<br/> 
and use the private key to sign certificates.<br/>
in order for the proxy server to listen and forward encrypted data,<br/>
it needs be able to performm tls handshakes and present tls certificate to authenticate their identity.<br/>
with this tool we can sign a fake CA certificate with the CA private key and pass it to the proxy server.<br/>

<br/>
in order for the target device to trust this fake CA, a CA certificate file must be inserted manually in target device root CAs list.<br/>
<br/>
<b>Note:</b> the target device will be expose to attacks as long as the custom CA is trusted.<br/>
MAKE SURE to remove your CA’s public key from target device’s list of root CAs as soon as you are done with this project!<br/>

### Proxy Server

mitm proxy server built using `Twisted` module, catchs tcp `connectionMade` and `dataReceived` methods using `Protocol` class.<br/>
it listens for normal http communication on port 80 and for encrypted tls communication on port 443.<br/>

## Dependencies

*   Scapy
*   PyDNS
*   PyOpenSSL
*   Twisted

## Usage
To show help:<br/>

`[-h]` - show program description and input parameters.<br/>
<br/>
To show list of network interfaces:<br/>

`[nic-scan]` - display device network interfaces.<br/>
<br/>
To generate certificate pem and pub files:<br/>

`[ca]` - certificate authority mode.<br/>
*    `[-n]` - fake certificate authority name.<br/>
*    `[-p]` - path for certificate file (ext .pem). (optional)<br/>
<br/>
To show target running services or scan for targets:<br/>

`[observe]` - observation mode.<br/>
*    `[-i]` - network interface index.<br/>
*    `[-a]` - perform target scan using arp sweep.<br/>
*    `[-t]` - target private ip address. (not needed if using arp)<br/>
<br/>
To start proxy server and itercept service:<br/>

`[proxy]` - proxy mode.<br/>
*    `[-i]` - network interface index.<br/>
*    `[-t]` - target private ip address.<br/>
*    `[-d]` - service domain name.<br/>
*    `[-s]` - service subdomains. (optional)<br/>
<br/>

## Examples

Generate certificate pem and pub file:<br/>

```
python .\main.py ca -n SOME-FAKE-CA-NAME
```
<br/>
Run proxy server:<br/>

```
python .\main.py proxy -i 16 -t 192.168.0.10 -d 'www.google.com'
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details