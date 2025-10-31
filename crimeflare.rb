#!/usr/bin/env ruby
# encoding: UTF-8
require 'net/http'
require 'open-uri'
require 'json'
require 'socket'
require 'optparse'

def banner()
red = "\033[01;31m"
green = "\033[01;32m"


puts "#{green}A simple tool written in Ruby for finding realtime ips behind CloudFlare."
puts "#{green}This tool is rather simple, it uses CrimeFlare to allow a bypass to CloudFlare protected domains."
puts "\n"
puts "\n"
puts "#{red}[!]This is a re-written version of the popular tool called 'HatCloud'. Many of the bugs have been fixed!"
puts " /      \           /  |                        /        |/  |
/$$$$$$  |  ______  $$/  _____  ____    ______  $$$$$$$$/ $$ |  ______    ______    ______  
$$ |  $$/  /      \ /  |/     \/    \  /      \ $$ |__    $$ | /      \  /      \  /      \ 
$$ |      /$$$$$$  |$$ |$$$$$$ $$$$  |/$$$$$$  |$$    |   $$ | $$$$$$  |/$$$$$$  |/$$$$$$  |
$$ |   __ $$ |  $$/ $$ |$$ | $$ | $$ |$$    $$ |$$$$$/    $$ | /    $$ |$$ |  $$/ $$    $$ |
$$ \__/  |$$ |      $$ |$$ | $$ | $$ |$$$$$$$$/ $$ |      $$ |/$$$$$$$ |$$ |      $$$$$$$$/ 
$$    $$/ $$ |      $$ |$$ | $$ | $$ |$$       |$$ |      $$ |$$    $$ |$$ |      $$       |
 $$$$$$/  $$/       $$/ $$/  $$/  $$/  $$$$$$$/ $$/       $$/  $$$$$$$/ $$/        $$$$$$$/ \e[0;0m \03>
"
puts "\n"
puts "#{green}Get Commands:"
puts "#{green}-h - Get the help for commands"
puts "\n"
end

options = {:bypass => nil, :massbypass => nil}
parser = OptionParser.new do|opts|

    opts.banner = "Example: ruby crimeflare.rb -b <target site> or ruby anticf.rb --byp <target site>"
    opts.on('-b ','--byp ', 'Discover real IP (bypass CloudFlare)', String)do |bypass|
    options[:bypass]=bypass;
    end

    opts.on('-o', '--out', 'Next release.', String) do |massbypass|
        options[:massbypass]=massbypass

    end

    opts.on('-h', '--help', 'Help') do
        banner()
        puts opts
        puts "Example: ./crimeflare.rb -b <domain> or ruby anticf.rb --byp <domain>"
        exit
    end
end

parser.parse!


banner()

if options[:bypass].nil?
    puts "Insert URL, domain or CloudFlare protected website. Included with: -b or --byp"
else
	option = options[:bypass]
	payload = URI ("http://www.crimeflare.info/cgi-bin/cfsearch.cgi")
	request = Net::HTTP.post_form(payload, 'cfS' => options[:bypass])

	response =  request.body
	nscheck = /No working nameservers are registered/.match(response)
	if( !nscheck.nil? )
		puts "[-] No valid URL. Is this a CloudFlare protected site?\n"
		exit
	end
	regex = /(\d*\.\d*\.\d*\.\d*)/.match(response)
	if( regex.nil? || regex == "" )
		puts "[-] No valid URL. Is this a CloudFlare protected site?\n"
		puts "[-] Alternately, maybe CrimeFlare is down?\n"
		puts "[-] Try doing it manually - http://www.crimeflare.info\n"
		exit
	end
	ip_real = IPSocket.getaddress (options[:bypass])

	puts "[+] Site analysis: #{option} "
	puts "[+] CloudFlare IP is #{ip_real} "
	puts "[+] Real IP is #{regex}"
	target = "http://ip-api.com/json/#{regex}"
	url = URI(target).read
	json = JSON.parse(url)
	puts "[+] Hostname: " + json['hostname']
	puts "[+] City: "  + json['city']
	puts "[+] Region: " + json['country']
	puts "[+] Location: " + json['loc']
	puts "[+] Organization: " + json['org']

end
