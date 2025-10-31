# Crypto Hunter Script


###
Exemplo de Enumeração DNS\n
./cryptohunter.rb -d exemplo.com

Exemplo de Varredura de Portas\n
./cryptohunter.rb -h 192.168.1.1 -p 80,443,8080

Exemplo de Consulta WHOIS\n 
./cryptohunter.rb -w exemplo.com

Exemplo de Geolocalização de IP \n
./cryptohunter.rb -g 8.8.8.8

###

<img src="https://media.discordapp.net/attachments/1433874664706539601/1433876177570889851/Screenshot_2025-10-31_at_07.50.11.png?ex=690648c0&is=6904f740&hm=51dba902c9d21f605f94d4523fa9ef0cd88bcac0edaf2d99bfc1ca2067e3ba96&=&format=webp&quality=lossless&width=1354&height=704" img>
- Dns enum com ruby
- Host Port scanner added
- Whois Added
- Geolocation Added
 
# Requirements 
- Ruby
- gem install whois json net-http-persistent
- sudo gem install whois json net-http-persistent
- sudo apt install ruby-dev build-essential
- gem install whois
