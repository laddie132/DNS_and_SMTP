# DNS_and_SMTP
This is a homework of Computer Network course including a dns server and a smtp client.

### DNS SERVER

- first to find ip address in local cache
- when not found in first step, query to the relay dns server
- support multiquery at the same time

#### Usage

`Usage: dns_server.exe [-d | -dd] [dns-server-ipaddr] [filename]`

> default relay server: 114.114.114.114
>
> default listen address: 0.0.0.0:53
>
> default local filename: dnsrelay.txt

### SMTP CLIENT

- send emails with smtp support
- automatically identify smtp servers

#### Usage

just run `smtp_clent.exe` and then step by tep with prompts