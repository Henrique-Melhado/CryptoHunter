#!/usr/bin/env ruby
# dns enumeration and port scanning tool by henriquemelhado
require 'socket'
require 'resolv'
require 'optparse'

def port_scan(host, ports)
  puts "Scanning #{host}..."
  ports.each do |port|
    begin
      socket = Socket.new(:INET, :STREAM)
      sockaddr = Socket.sockaddr_in(port, host)
      socket.connect_nonblock(sockaddr)
    rescue Errno::EINPROGRESS
      # Connection in progress
    end

    _, sockets, _ = IO.select(nil, [socket], nil, 0.1)

    if sockets
      puts "Port #{port} is open."
      sockets.first.close
    end
  end
end

def dns_enum(domain)
  puts "Enumerating DNS for #{domain}..."
  record_types = [
    Resolv::DNS::Resource::IN::A,
    Resolv::DNS::Resource::IN::AAAA,
    Resolv::DNS::Resource::IN::CNAME,
    Resolv::DNS::Resource::IN::MX,
    Resolv::DNS::Resource::IN::NS,
    Resolv::DNS::Resource::IN::TXT
  ]

  record_types.each do |type|
    begin
      records = Resolv::DNS.new.getresources(domain, type)
      if records.any?
        puts "--- #{type.to_s.split('::').last} records ---"
        records.each do |record|
          case record
          when Resolv::DNS::Resource::IN::A, Resolv::DNS::Resource::IN::AAAA
            puts record.address
          when Resolv::DNS::Resource::IN::CNAME
            puts record.name
          when Resolv::DNS::Resource::IN::MX
            puts "Preference: #{record.preference}, Exchange: #{record.exchange}"
          when Resolv::DNS::Resource::IN::NS
            puts record.name
          when Resolv::DNS::Resource::IN::TXT
            puts record.strings.join(' ')
          end
        end
      end
    rescue Resolv::ResolvError => e
      # puts "Couldn't resolve #{type} records for #{domain}: #{e}"
    end
  end
end

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: scanner.rb [options]"

  opts.on("-d", "--domain [DOMAIN]", "Domain to enumerate") do |domain|
    options[:domain] = domain
  end

  opts.on("-h", "--host [HOST]", "Host to scan") do |host|
    options[:host] = host
  end

  opts.on("-p", "--ports [PORTS]", "Ports to scan (e.g., 1-100,80,443)") do |ports|
    options[:ports] = ports
  end

  opts.on_tail("-H", "--help", "Show this message") do
    puts opts
    exit
  end
end.parse!

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
    ports = (1..1024).to_a
  end
  port_scan(options[:host], ports.uniq.sort)
end

if options.empty?
  puts "Please specify a domain or host to scan."
  puts "Use -H for help."
end
