#!/usr/bin/env ruby
# encoding: utf-8
# dns enumeration and port scanning tool by henriquemelhado (Improved by Manus)

require 'socket'
require 'resolv'
require 'optparse'
require 'whois'
require 'net/http'
require 'json'

# Módulo para colorização de saída no terminal
module Colors
  RED    = "\e[31m"
  GREEN  = "\e[32m"
  YELLOW = "\e[33m"
  BLUE   = "\e[34m"
  MAGENTA= "\e[35m"
  CYAN   = "\e[36m"
  WHITE  = "\e[37m"
  BOLD   = "\e[1m"
  RESET  = "\e[0m"
end

# Banner do programa
def print_banner
  puts "#{Colors::CYAN}#{Colors::BOLD}
  _  _         _         _  _           _
 | || |___ ___| |_ ___  | || |_ _ _ ___| |_
 | __ / -_|_-<|  _/ _ \\ | __ | '_| '_/ -_)  _|
 |_||_\\___/__/ \\__\\___/ |_||_|_| |_| \\___|\\__|
  #{Colors::RESET}
  #{Colors::YELLOW}HostHunter - Ferramenta de Enumeração DNS e Varredura de Portas#{Colors::RESET}
  #{Colors::MAGENTA}Criado por Crypto (Cyber Security specialist)#{Colors::RESET}
  "
end

# Função de varredura de portas com saída colorida
def port_scan(host, ports)
  puts "\n#{Colors::BLUE}#{Colors::BOLD}[+] Varredura de Portas Iniciada#{Colors::RESET}"
  puts "#{Colors::BLUE}Alvo: #{Colors::WHITE}#{host}#{Colors::RESET}"
  puts "#{Colors::BLUE}Portas a serem verificadas: #{Colors::WHITE}#{ports.size}#{Colors::RESET}"
  
  open_ports = []
  
  ports.each do |port|
    begin
      socket = Socket.new(:INET, :STREAM)
      sockaddr = Socket.sockaddr_in(port, host)
      
      # Tenta conectar sem bloqueio
      socket.connect_nonblock(sockaddr)
      
    rescue Errno::EINPROGRESS
      # Conexão em progresso, usa IO.select para verificar se a conexão foi estabelecida
      if IO.select(nil, [socket], nil, 0.1)
        puts "#{Colors::GREEN}  [ABERTA] Porta #{port}#{Colors::RESET}"
        open_ports << port
        socket.close
      else
        # Porta fechada ou filtrada (timeout)
        socket.close
      end
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH
      # Porta fechada ou host inacessível
    rescue StandardError => e
      # Outros erros
      # puts "#{Colors::RED}  [ERRO] Porta #{port}: #{e.message}#{Colors::RESET}"
    end
  end
  
  puts "\n#{Colors::GREEN}#{Colors::BOLD}[+] Varredura de Portas Concluída#{Colors::RESET}"
  puts "#{Colors::GREEN}Portas Abertas Encontradas: #{Colors::WHITE}#{open_ports.size}#{Colors::RESET}"
end

# Função de enumeração DNS com saída colorida
def dns_enum(domain)
  puts "\n#{Colors::BLUE}#{Colors::BOLD}[+] Enumeração DNS Iniciada#{Colors::RESET}"
  puts "#{Colors::BLUE}Domínio: #{Colors::WHITE}#{domain}#{Colors::RESET}"
  
  record_types = [
    Resolv::DNS::Resource::IN::A,
    Resolv::DNS::Resource::IN::AAAA,
    Resolv::DNS::Resource::IN::CNAME,
    Resolv::DNS::Resource::IN::MX,
    Resolv::DNS::Resource::IN::NS,
    Resolv::DNS::Resource::IN::TXT
  ]
  
  record_types.each do |type|
    type_name = type.to_s.split('::').last
    begin
      records = Resolv::DNS.new.getresources(domain, type)
      if records.any?
        puts "\n#{Colors::YELLOW}--- Registros #{type_name} ---#{Colors::RESET}"
        records.each do |record|
          output = case record
                   when Resolv::DNS::Resource::IN::A, Resolv::DNS::Resource::IN::AAAA
                     "#{Colors::GREEN}#{record.address}#{Colors::RESET}"
                   when Resolv::DNS::Resource::IN::CNAME
                     "#{Colors::GREEN}#{record.name}#{Colors::RESET}"
                   when Resolv::DNS::Resource::IN::MX
                     "#{Colors::WHITE}Preferência: #{record.preference}, Exchange: #{Colors::GREEN}#{record.exchange}#{Colors::RESET}"
                   when Resolv::DNS::Resource::IN::NS
                     "#{Colors::GREEN}#{record.name}#{Colors::RESET}"
                   when Resolv::DNS::Resource::IN::TXT
                     "#{Colors::WHITE}#{record.strings.join(' ')}#{Colors::RESET}"
                   else
                     "#{Colors::WHITE}#{record.to_s}#{Colors::RESET}"
                   end
          puts "  #{output}"
        end
      end
    rescue Resolv::ResolvError
      # Ignora erros de resolução
    end
  end
  
  puts "\n#{Colors::GREEN}#{Colors::BOLD}[+] Enumeração DNS Concluída#{Colors::RESET}"
end

# Função de consulta WHOIS
def whois_lookup(target)
  puts "\n#{Colors::BLUE}#{Colors::BOLD}[+] Consulta WHOIS Iniciada#{Colors::RESET}"
  puts "#{Colors::BLUE}Alvo: #{Colors::WHITE}#{target}#{Colors::RESET}"
  
  begin
    client = Whois::Client.new
    record = client.lookup(target)
    
    puts "\n#{Colors::YELLOW}--- Informações WHOIS ---#{Colors::RESET}"
    puts record.to_s
    
  rescue Whois::WebInterfaceError => e
    puts "#{Colors::RED}  [ERRO] O servidor WHOIS requer interação via web.#{Colors::RESET}"
  rescue Whois::ResponseIsThrottled => e
    puts "#{Colors::RED}  [ERRO] A consulta WHOIS foi limitada por taxa. Tente novamente mais tarde.#{Colors::RESET}"
  rescue Whois::ResponseIsUnavailable => e
    puts "#{Colors::RED}  [ERRO] A resposta WHOIS está indisponível.#{Colors::RESET}"
  rescue StandardError => e
    puts "#{Colors::RED}  [ERRO] Falha na consulta WHOIS: #{e.message}#{Colors::RESET}"
  end
  
  puts "\n#{Colors::GREEN}#{Colors::BOLD}[+] Consulta WHOIS Concluída#{Colors::RESET}"
end

# Função de geolocalização (usa um serviço público de API)
def geolocate_ip(ip)
  puts "\n#{Colors::BLUE}#{Colors::BOLD}[+] Geolocalização Iniciada#{Colors::RESET}"
  puts "#{Colors::BLUE}IP: #{Colors::WHITE}#{ip}#{Colors::RESET}"
  
  uri = URI("http://ip-api.com/json/#{ip}")
  
  begin
    response = Net::HTTP.get(uri)
    data = JSON.parse(response)
    
    if data['status'] == 'success'
      puts "\n#{Colors::YELLOW}--- Detalhes de Geolocalização ---#{Colors::RESET}"
      puts "#{Colors::WHITE}  País: #{Colors::GREEN}#{data['country']} (#{data['countryCode']})#{Colors::RESET}"
      puts "#{Colors::WHITE}  Região: #{Colors::GREEN}#{data['regionName']} (#{data['region']})#{Colors::RESET}"
      puts "#{Colors::WHITE}  Cidade: #{Colors::GREEN}#{data['city']}#{Colors::RESET}"
      puts "#{Colors::WHITE}  CEP: #{Colors::GREEN}#{data['zip']}#{Colors::RESET}"
      puts "#{Colors::WHITE}  Latitude/Longitude: #{Colors::GREEN}#{data['lat']}, #{data['lon']}#{Colors::RESET}"
      puts "#{Colors::WHITE}  Fuso Horário: #{Colors::GREEN}#{data['timezone']}#{Colors::RESET}"
      puts "#{Colors::WHITE}  Provedor (ISP): #{Colors::GREEN}#{data['isp']}#{Colors::RESET}"
      puts "#{Colors::WHITE}  Organização: #{Colors::GREEN}#{data['org']}#{Colors::RESET}"
    else
      puts "#{Colors::RED}  [ERRO] Falha ao obter dados de geolocalização: #{data['message']}#{Colors::RESET}"
    end
    
  rescue StandardError => e
    puts "#{Colors::RED}  [ERRO] Falha na requisição de geolocalização: #{e.message}#{Colors::RESET}"
  end
  
  puts "\n#{Colors::GREEN}#{Colors::BOLD}[+] Geolocalização Concluída#{Colors::RESET}"
end

# Função principal para processar as opções
def main
  options = {}
  
  opt_parser = OptionParser.new do |opts|
    opts.banner = "#{Colors::BOLD}Uso: #{Colors::WHITE}#{$0} [opções]#{Colors::RESET}"
    opts.separator ""
    opts.separator "#{Colors::BOLD}Opções de Ação:#{Colors::RESET}"
    
    opts.on("-d", "--domain DOMAIN", "#{Colors::CYAN}Domínio para enumeração DNS (e.g., example.com)#{Colors::RESET}") do |domain|
      options[:domain] = domain
    end
    
    opts.on("-h", "--host HOST", "#{Colors::CYAN}Host (IP ou Domínio) para varredura de portas (e.g., 192.168.1.1)#{Colors::RESET}") do |host|
      options[:host] = host
    end
    
    opts.on("-w", "--whois TARGET", "#{Colors::CYAN}Realiza consulta WHOIS em um domínio ou IP (e.g., example.com)#{Colors::RESET}") do |target|
      options[:whois] = target
    end
    
    opts.on("-g", "--geo IP", "#{Colors::CYAN}Realiza geolocalização de um endereço IP (e.g., 8.8.8.8)#{Colors::RESET}") do |ip|
      options[:geo] = ip
    end
    
    opts.separator ""
    opts.separator "#{Colors::BOLD}Opções de Varredura de Portas:#{Colors::RESET}"
    
    opts.on("-p", "--ports PORTS", "#{Colors::CYAN}Portas a serem varridas (e.g., 1-100,80,443). Padrão: 1-1024.#{Colors::RESET}") do |ports|
      options[:ports] = ports
    end
    
    opts.separator ""
    opts.separator "#{Colors::BOLD}Opções Gerais:#{Colors::RESET}"
    
    opts.on_tail("-H", "--help", "#{Colors::CYAN}Mostra esta mensagem de ajuda#{Colors::RESET}") do
      print_banner
      puts opts
      exit
    end
  end
  
  begin
    opt_parser.parse!
  rescue OptionParser::InvalidOption => e
    puts "#{Colors::RED}#{Colors::BOLD}[ERRO] Opção inválida: #{e}#{Colors::RESET}"
    puts "Use -H ou --help para ver as opções."
    exit 1
  end
  
  # Se nenhuma opção foi fornecida, mostra o banner e a ajuda
  if options.empty?
    print_banner
    puts opt_parser
    exit
  end
  
  # Lógica de execução
  print_banner
  
  # Executa as funcionalidades em ordem
  if options[:domain]
    dns_enum(options[:domain])
  end
  
  if options[:host]
    ports = []
    if options[:ports]
      options[:ports].split(',').each do |p|
        if p.include?('-')
          range = p.split('-')
          ports.concat((range[0].to_i..range[1].to_i).to_a)
        else
          ports << p.to_i
        end
      end
    else
      # Padrão: 1-1024
      ports = (1..1024).to_a
    end
    port_scan(options[:host], ports.uniq.sort)
  end
  
  if options[:whois]
    whois_lookup(options[:whois])
  end
  
  if options[:geo]
    geolocate_ip(options[:geo])
  end
end

main
