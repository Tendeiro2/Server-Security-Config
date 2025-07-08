# Server-Security-Config
Configuração e hardening de um servidor Linux com testes de segurança utilizando ferramentas como Nmap.

Este repositório documenta um projeto realizado no âmbito da unidade curricular de Segurança de Sistemas do 3.º ano do curso de Engenharia Informática. O objetivo foi configurar e reforçar a segurança de um servidor Linux, garantindo que este estivesse preparado para ser exposto à Internet. Foram implementadas medidas como a configuração do SSH para funcionar apenas com autenticação por chave assimétrica, a instalação do Fail2Ban para proteção contra ataques de força bruta, a configuração do SSHTTP/SSLH para multiplexação de conexões e a obtenção de um certificado SSL/TLS através do Let's Encrypt.

Foi também configurada uma firewall para controlo de tráfego e reforço da segurança da infraestrutura, conforme solicitado no enunciado do projeto. Além disso, foram instalados e testados outros serviços, como Port Knocking e WireGuard. Por fim, a eficácia das medidas de segurança foi validada através de testes práticos utilizando ferramentas como o Nmap.
