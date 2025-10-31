# Crypto Hunter Script


<img src="https://media.discordapp.net/attachments/1433874664706539601/1433876177570889851/Screenshot_2025-10-31_at_07.50.11.png?ex=690648c0&is=6904f740&hm=51dba902c9d21f605f94d4523fa9ef0cd88bcac0edaf2d99bfc1ca2067e3ba96&=&format=webp&quality=lossless&width=1354&height=704" img>
- Dns enum com ruby
- Host Port scanner added
- Whois Added
- Geolocation Added
- Funcionalidade Adicionada -P ou --skip-ping: 

Esta opção pula a verificação de atividade do host antes de iniciar a varredura de portas. Isso é útil quando o host bloqueia pacotes ICMP (ping) ou outras tentativas de verificação de atividade, mas você ainda quer tentar escanear as portas.

# Requirements 
- Ruby
- gem install whois json net-http-persistent
- sudo gem install whois json net-http-persistent
- sudo apt install ruby-dev build-essential
- gem install whois


- Enumeração DNS
  
```./cryptohunter.rb -d exemplo.com```

- Varredura de Portas

```./cryptohunter.rb -h 192.168.1.1 -p 80,443,8080```

- Varredura de Portas sem ping
``` ./cryptohunter.rb -h [HOST] -p [PORTAS] -P ```

- Consulta WHOIS
  
```./cryptohunter.rb -w exemplo.com```

- Geolocalização de IP

```./cryptohunter.rb -g 8.8.8.8```

