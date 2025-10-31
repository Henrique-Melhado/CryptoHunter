#!/usr/bin/env ruby

require 'resolv'
# dns enumeration script simples
def enumerate_dns(domain)
  puts "Starting DNS enumeration for #{domain}..."

  record_types = [
    Resolv::DNS::Resource::IN::A,
    Resolv::DNS::Resource::IN::AAAA,
    Resolv::DNS::Resource::IN::CNAME,
    Resolv::DNS::Resource::IN::MX,
    Resolv::DNS::Resource::IN::NS,
    Resolv::DNS::Resource::IN::TXT,
    Resolv::DNS::Resource::IN::SOA
  ]

  dns = Resolv::DNS.new

  record_types.each do |record_type|
    begin
      records = dns.getresources(domain, record_type)
      type_name = record_type.to_s.split("::").last
      puts "\n--- #{type_name} RECORDS ---"
      if records.any?
        records.each do |record|
          case record
          when Resolv::DNS::Resource::IN::A, Resolv::DNS::Resource::IN::AAAA
            puts record.address.to_s
          when Resolv::DNS::Resource::IN::CNAME
            # CNAME stores the canonical name in 'name' (fallback to inspect if missing)
            puts(record.name.to_s) rescue (puts record.inspect)
          when Resolv::DNS::Resource::IN::NS
            puts record.name.to_s
          when Resolv::DNS::Resource::IN::MX
            puts "Preference: #{record.preference}, Exchange: #{record.exchange}"
          when Resolv::DNS::Resource::IN::TXT
            puts record.strings.join(" ")
          when Resolv::DNS::Resource::IN::SOA
            puts "MNAME: #{record.mname}, RNAME: #{record.rname}, Serial: #{record.serial}"
          else
            puts record.inspect
          end
        end
      else
        puts "No records found."
      end
    rescue Resolv::ResolvError => e
      puts "Error fetching #{type_name} records: #{e.message}"
    end
  end

  puts "\nDNS enumeration finished."
end

if ARGV.empty?
  puts "Usage: #{$0} <domain>"
  exit 1
end

enumerate_dns(ARGV[0])
