# STORMNET-MCSTORM-Client
STORMNET allows secure encrypted communication on a decentralized network. MCSTORM built in.



## Introduction

After the FBI's big seizure of stressors in December 2022, most providers just moved their services to a new domain name and continue their operations as usual, using the same unsecured and extremely dangerous techniques both to the providers as well as their clients. Since then, there have been new reports of stressor websites being seized and their users arrested.



## Current techniques

Cloudflare is a popular service offering various benefits such as improved website performance, security features, and protection against Distributed Denial of Service (DDoS) attacks. One of its main features stressor services use it for is the ability to hide the webserver's IP address and keep the hosting provider unknown, therefore protecting it from being reported to the hosting provider by overzealous individuals.

Additionally, Cloudflare provides SSL certificates to enable secure connections between clients and websites. However, Cloudflare's default Flexible SSL mode presents certain privacy and security issues due to its lack of end-to-end encryption.

![Stresser website using cloudflare](image/stresser-cloudflare.png)

![Legend](image/legend.png)

Unencrypted communications are particularly vulnerable to Man-in-the-Middle (MITM) attacks, which can compromise the privacy and security of the data being transmitted. A Man-in-the-Middle attack is a type of cyber attack in which an unauthorized third party, such as hackers or FBI, intercepts and potentially alters the communication between two parties, usually without their knowledge. The attacker positions themselves between the victim (client) and the intended recipient (server), effectively becoming a "middleman" in the communication process.

In Cloudflare's Flexible SSL mode, data is only encrypted between the client and Cloudflare's servers. The communication between Cloudflare and the origin server remains unencrypted, leaving the transmitted data exposed to logging and manipulation. This lack of end-to-end encryption can create security vulnerabilities and undermine the privacy of users. Not only can the stressor itself view the unencrypted data transmitted between the client and the origin server, but other intermediaries, such as the stressors webserver's hosting, can also potentially see and log all activity directly linked to IP addresses leading to breaches in privacy and potential arrests of the stressor's users.

Unencrypted communication between the stressor's web server and its attack servers can also be easily intercepted by unauthorized parties, such as hackers, the FBI, or other malicious actors. This can lead to unauthorized access to sensitive information, including user data, personal data, and confidential business data.

Apart from unencrypted communication, there are other security issues that can arise when interacting with websites in general. These concerns include the logging of IP addresses, browser information, and user activity by Cloudflare servers and the websites themselves. Stressor websites almost always claim they remove logs every day, but this is most of the time not true. If the website stores this data in an insecure manner or does not employ proper security measures, which is very common, it can become vulnerable to attacks such as SQL injection or seizure-of-servers attacks by the FBI.



## MCSTORM's new approach

We introduce a new groundbreaking technology designed to comprehensively address these challenges, providing a robust and holistic solution for securing online communications and preserving user privacy. Our novel approach combines advanced cryptography, decentralization, and anonymity techniques, which work together to create a secure and private environment for users, completely removes the risk of seizure of domain names (because it does not use any domain names) and significantly reducing the risk of seizure of servers, identity discovery, and unauthorized access to sensitive information.

![MCSTORM using STORMNET](image/STORMNET-mcstorm.png)
