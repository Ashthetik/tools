#!/usr/bin/env ruby

require 'resolv'
require 'socket'
require 'optparse'
require 'timeout'
require 'ipaddr'
require 'openssl'
require 'net/http'
require 'net/https'

puts <<~BANNER
\n
\e[35m  
  ██████╗ ██╗   ██╗██╗     ███████╗███████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ██╔══██╗██║   ██║██║     ██╔════╝██╔════╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝██║   ██║██║     ███████╗█████╗  ██║     ███████║█████╗  ██║     █████╔╝ 
  ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
  ██║     ╚██████╔╝███████╗███████║███████╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                                     
            Network Stability & Security Testing Tool v0.1 BETA
  ═══════════════════════════════════════════════════════════════════════════════════\e[0m\n
BANNER

class StabilityCheck
  NUM_PACKETS = 4
  ICMP_ECHO_REQUEST = 8

  WEBSITES = ["google.com"].freeze

  DNS_SERVERS = [
    { name: "Google", address: "8.8.8.8" },
    { name: "Quad9", address: "9.9.9.9" },
    { name: "OpenDNS", address: "208.67.222.222" },
    { name: "Cloudflare", address: "1.1.1.1" },
    { name: "Level3", address: "4.2.2.2" },
    { name: "Norton ConnectSafe", address: "199.85.126.10" },
    { name: "Comodo Secure DNS", address: "8.26.56.26" },
    { name: "Verisign", address: "64.6.65.6" },
    { name: "Yandex.DNS", address: "77.88.8.8" },
    { name: "Neustar", address: "156.154.70.5" }
  ].freeze

  def initialize
    @success_times = []
    @hops = []
  end

  def test_dns_performance(server_name, server_address = nil)
    response_times = []
    
    resolver = if server_address
                 Resolv::DNS.new(nameserver: [server_address])
               else
                 Resolv::DNS.new
               end

    WEBSITES.each do |website|
      begin
        start_time = Time.now
        resolver.getaddress(website)
        end_time = Time.now
        response_times << (end_time - start_time)
      rescue => e
        puts "[\e[31mERROR] Error querying #{website} with #{server_name}: #{e.message}\e[0m"
      end
    end

    average_time = response_times.empty? ? Float::INFINITY : response_times.sum / response_times.length
    puts "\e[36m[INFO] Average response time for #{server_name}: #{format('%.4f', average_time)} seconds\e[0m"
    average_time
  ensure
    resolver&.close if resolver.respond_to?(:close)
  end

  def run_dns_test
    puts "\n\e[33m[DNS] Testing with the system's default DNS resolver...\e[0m"
    default_dns_time = test_dns_performance("Default DNS Resolver")

    dns_performance = []
    DNS_SERVERS.each do |dns_server|
      puts "\n\e[33m[DNS] Testing with #{dns_server[:name]} DNS server...\e[0m"
      avg_time = test_dns_performance(dns_server[:name], dns_server[:address])
      dns_performance << [dns_server[:name], avg_time]
    end

    puts "\n" + "=" * 80
    puts "DNS PERFORMANCE SUMMARY"
    puts "=" * 80
    puts "Default DNS Resolver: #{format('%.2f', default_dns_time * 1000)} ms"
    dns_performance.each do |server, time|
      puts "#{server}: #{format('%.2f', time * 1000)} ms"
    end
    puts "=" * 80
  end

  def ping(host, timeout = 1)
    puts "\n\e[33m[PING] Pinging #{host} with #{NUM_PACKETS} packets...\e[0m"
    
    begin
      dest_ip = Resolv.getaddress(host)
      puts "\e[33m[PING] PING #{host} (#{dest_ip})\e[0m"
      
      NUM_PACKETS.times do |i|
        start_time = Time.now
        
        # Use system ping command for reliability
        ping_cmd = if RUBY_PLATFORM.match?(/win32|win64|\.NET|windows|cygwin|mingw32/i)
                     "ping -n 1 -w #{timeout * 1000} #{dest_ip}"
                   else
                     "ping -c 1 -W #{timeout} #{dest_ip}"
                   end
        
        result = `#{ping_cmd} 2>/dev/null`
        end_time = Time.now
        
        if $?.success?
          # Extract time from ping output (simplified)
          time_match = result.match(/time[<=](\d+\.?\d*)\s*ms/i)
          if time_match
            response_time = time_match[1].to_f
            @success_times << response_time
            puts "\e[33m[PING] Reply from #{dest_ip}: time=#{response_time}ms\e[0m"
          else
            estimated_time = (end_time - start_time) * 1000
            @success_times << estimated_time
            puts "\e[33m[PING] Reply from #{dest_ip}: time~#{format('%.2f', estimated_time)}ms\e[0m"
          end
        else
          puts "\e[32m[PING] Request timeout for packet #{i + 1}\e[0m"
        end
        
        sleep(1) unless i == NUM_PACKETS - 1
      end
      
      if @success_times.any?
        avg_time = @success_times.sum / @success_times.length
        puts "\e[36m[PING] Average response time: #{format('%.2f', avg_time)}ms\e[0m"
      end
      
    rescue Resolv::ResolvError => e
      puts "\e[31m[ERROR] Cannot resolve hostname #{host}: #{e.message}\e[0m"
    rescue => e
      puts "\e[31m[ERROR] Ping failed: #{e.message}\e[0m"
    end
  end

  def traceroute(dest, max_hops = 30, timeout = 2)
    puts "\n\e[34m[TRACEROUTE] Traceroute to #{dest} (max hops: #{max_hops}, timeout: #{timeout}s)\e[0m"
    
    begin
      dest_ip = Resolv.getaddress(dest)
      puts "\e[34m[TRACEROUTE] Tracing route to #{dest} (#{dest_ip})\e[0m"
      
      # Use system traceroute/tracert command
      trace_cmd = if RUBY_PLATFORM.match?(/win32|win64|\.NET|windows|cygwin|mingw32/i)
                    "tracert -h #{max_hops} -w #{timeout * 1000} #{dest_ip}"
                  else
                    "traceroute -m #{max_hops} -w #{timeout} #{dest_ip}"
                  end
      
      puts "\e[34m[TRACEROUTE] Running: #{trace_cmd.split.first}...\e[0m"
      
      IO.popen(trace_cmd, err: [:child, :out]) do |io|
        hop_count = 0
        io.each_line do |line|
          line.strip!
          next if line.empty?
          
          # Skip header lines
          next if line.match?(/traceroute|tracing|over a maximum/i)
          
          # Parse hop information (simplified)
          if line.match?(/^\s*(\d+)/)
            hop_count += 1
            
            # Extract IP addresses from the line
            ips = line.scan(/(\d+\.\d+\.\d+\.\d+)/).flatten.uniq
            times = line.scan(/(\d+\.?\d*)\s*ms/i).flatten
            
            if ips.any?
              ip = ips.first
              time_info = times.any? ? "#{times.first}ms" : "* ms"
              puts "#{format('%2d', hop_count)}  #{ip} (#{time_info})"
              @hops << [hop_count, ip]
            else
              puts "#{format('%2d', hop_count)}  * * * Request timed out"
              @hops << [hop_count, "No Response"]
            end
          end
        end
      end
      
      puts "\e[36m[TRACEROUTE] Traceroute completed with #{@hops.length} hops\e[0m"
      
    rescue Resolv::ResolvError => e
      puts "\e[31m[ERROR] Cannot resolve hostname #{dest}: #{e.message}\e[0m"
    rescue => e
      puts "\e[31m[ERROR] Traceroute failed: #{e.message}\e[0m"
    end
  end

  def display_trace_summary
    return if @hops.empty?
    
    puts "\n" + "=" * 60
    puts "TRACEROUTE SUMMARY"
    puts "=" * 60
    
    @hops.each do |hop_num, ip|
      status = ip == "No Response" ? "\e[33m[TIMEOUT]" : "[OK]"
      puts "#{status} Hop #{format('%2d', hop_num)}: #{ip}\e[0m"
    end
    puts "=" * 60
  end

  def run_full_test(destination, max_hops: 30, timeout: 2)
    puts "\n\e[34m[INFO] Testing Websites:\e[0m"
    WEBSITES.each { |website| puts "  - #{website}" }

    puts "\n" + "=" * 80
    puts "STARTING COMPREHENSIVE NETWORK TEST"
    puts "=" * 80

    puts "\nTRACEROUTE TEST"
    puts "-" * 40
    traceroute(destination, max_hops, timeout)
    display_trace_summary

    puts "\nPING TEST"
    puts "-" * 40
    ping(destination, timeout)

    puts "\nDNS PERFORMANCE TEST"
    puts "-" * 40
    run_dns_test
  end
end

class NetworkSecurity
  def initialize
    @timeout = 3
  end

  def scan_port(host, port)
    begin
      Timeout::timeout(@timeout) do
        socket = TCPSocket.new(host, port)
        socket.close
        return true
      end
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Timeout::Error
      return false
    end
  end

  def scan_ports(host, ports)
    results = {}
    puts "\e[34m[INFO] Scanning ports on #{host}...\e[0m"

    ports.each do |port|
      if scan_port(host, port)
        puts "Port #{port}: \e[32mOPEN\e[0m\n"
        results[port] = :open

        banner = grab_banner(host, port)
        puts "  Banner: #{banner}" if banner
      else
        results[port] = :closed
      end
    end

    results
  end

  def grab_banner(host, port) 
    begin
      Timeout::timeout(@timeout) do
        socket = TCPSocket.new(host, port)
        socket.write("HEAD / HTTP/1.0\r\n\r\n") if port == 80
        socket.write("GET / HTTP/1.1\r\nHost: #{host}\r\n\r\n") if port == 80

        banner = socket.recv(1024).strip
        socket.close

        return banner unless banner.empty?
      end
    rescue
      nil
    end
  end

  def check_http_headers(url)
    uri = URI(url)

    begin
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true if uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if uri.scheme == 'https'

      request = Net::HTTP::Get.new(uri)
      response = http.request(request)

      security_headers = {
        'X-Frame-Options' => response['X-Frame-Options'],
        'X-Content-Type-Options' => response['X-Content-Type-Options'],
        'X-XSS-Protection' => response['X-XSS-Protection'],
        'Strict-Transport-Security' => response['Strict-Transport-Security'],
        'Content-Security-Policy' => response['Content-Security-Policy'],
        'Referrer-Policy' => response['Referrer-Policy']
      }

      puts "\nHTTP Security Headers for #{url}:\n"
      security_headers.each do |header, value|
        status = value ? "\e[33mSET: #{value}\e[0m" : "\e[31mMISSING\e[0m"
        puts "#{header}: #{status}"
      end

      security_headers
    rescue => e
      puts "\e[31m[ERROR] Error checking Security Headers: #{e.message}\e[0m"
      nil
    end
  end

  def check_ssl_certificate(hostname, port = 443)
    begin
      tcp_socket = TCPSocket.new(hostname, port)
      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
      ssl_socket.connect
      
      cert = ssl_socket.peer_cert
      
      puts "\nSSL Certificate Information for #{hostname}:"
      puts "  Subject: #{cert.subject}"
      puts "  Issuer: #{cert.issuer}"
      puts "  Valid From: #{cert.not_before}"
      puts "  Valid Until: #{cert.not_after}"
      puts "  Serial Number: #{cert.serial}"
      
      # Check if certificate is expired
      if cert.not_after < Time.now
        puts "  STATUS: EXPIRED"
      elsif cert.not_before > Time.now
        puts "  STATUS: NOT YET VALID"
      else
        puts "  STATUS: VALID"
      end
      
      ssl_socket.close
      tcp_socket.close
      
      cert
    rescue => e
      puts "\e[31mSSL Error: #{e.message}\e[0m"
      nil
    end
  end

  def dns_enumeration(domain)
    puts "\nDNS Enumeration for #{domain}:"
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    results = {}
    
    record_types.each do |type|
      begin
        resolver = Resolv::DNS.new
        records = resolver.getresources(domain, Resolv::DNS::Resource::IN.const_get(type))
        
        if records.any?
          puts "  #{type} Records:"
          records.each do |record|
            case type
            when 'A', 'AAAA'
              puts "    #{record.address}"
            when 'MX'
              puts "    #{record.preference} #{record.exchange}"
            when 'NS'
              puts "    #{record.name}"
            when 'TXT'
              puts "    #{record.data}"
            when 'CNAME'
              puts "    #{record.name}"
            end
          end
          results[type] = records
        end
      rescue => e
        if e.empty?
          puts '\e[31m[ERROR] Record Type Not Found\e[0m'
        else
          puts "\e[31m[ERROR] #{e.message}\e[0m"
        end
      end
    end
    
    results
  end

  def subdomain_enumeration(domain)
    common_subdomains = %w[
      www mail ftp admin test dev staging api blog shop forum
      support help docs wiki m mobile app apps cdn static
      secure vpn remote access portal login dashboard panel
      admin administrator root server mail email pop imap smtp
    ]
    
    puts "\nSubdomain Enumeration for #{domain}:"
    found_subdomains = []
    
    common_subdomains.each do |sub|
      subdomain = "#{sub}.#{domain}"
      begin
        Resolv.getaddress(subdomain)
        puts "  Found: #{subdomain}"
        found_subdomains << subdomain
      rescue Resolv::ResolvError
        # TODO: Do error resolve
      end
    end
    
    found_subdomains
  end

  def scan_network_range(network_cidr, ports = [22, 80, 443])
    begin
      network = IPAddr.new(network_cidr)
      puts "\nScanning network range: #{network_cidr}"
      
      network.to_range.each do |ip|
        # Skip network and broadcast addresses
        next if ip == network.to_range.first || ip == network.to_range.last
        
        puts "\nScanning #{ip}..."
        open_ports = []
        
        ports.each do |port|
          if scan_port(ip.to_s, port)
            puts "  Port #{port}: \e[32mOPEN\e[0m"
            open_ports << port
          end
        end
        
        if open_ports.any?
          puts "  Active host with open ports: #{open_ports.join(', ')}"
        end
      end
    rescue => e
      puts "\e[31mNetwork scan error: #{e.message}\e[0m"
    end
  end

  def enumerate_http_methods(url)
    uri = URI(url)
    methods = %w[GET POST PUT DELETE HEAD OPTIONS TRACE CONNECT PATCH]
    
    puts "\nHTTP Methods allowed on #{url}:"
    allowed_methods = []
    
    methods.each do |method|
      begin
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true if uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if uri.scheme == 'https'
        
        request = Net::HTTP.const_get(method.capitalize).new(uri.path)
        response = http.request(request)
        
        if response.code.to_i < 500  # Not server error
          puts "  #{method}: #{response.code} #{response.message}"
          allowed_methods << method
        end
      rescue => e
        puts "  \e[33m#{method}: ERROR - #{e.message}\e[0m"
      end
    end
    
    allowed_methods
  end

  def basic_vulnerability_scan(host, port = 80)
    puts "\nBasic Vulnerability Scan for #{host}:#{port}"
    
    # Check for common files/directories
    common_paths = %w[
      /admin /administrator /login /wp-admin /phpmyadmin
      /.git /.svn /backup /config /test /debug
      /robots.txt /sitemap.xml /.htaccess /web.config
    ]
    
    base_url = port == 443 ? "https://#{host}" : "http://#{host}"
    
    common_paths.each do |path|
      begin
        uri = URI("#{base_url}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true if uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if uri.scheme == 'https'
        
        response = http.get(path)
        
        if response.code.to_i == 200
          puts "  Found: #{path} (#{response.code})"
        elsif response.code.to_i == 403
          puts "  Forbidden: #{path} (#{response.code})"
        end
      rescue => e
        # Path not accessible
        puts nil ? "ERROR" : e.message
      end
    end
  end

  def run_full_test(host)
    puts '=' * 80

    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

    scan_ports(host, common_ports)
    check_http_headers("https://#{host}")
    check_ssl_certificate("https://#{host}")
    dns_enumeration(host)
    # TODO: Fix the following function:
    # basic_vulnerability_scan(host)
  end
end

# Command line interface
def main
  options = { max_hops: 30, timeout: 2 }
  
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [OPTIONS] DESTINATION"
    opts.separator ""
    opts.separator "Options:"
    
    opts.on("-m", "--max-hops HOPS", Integer, "Maximum number of hops (default: 30)") do |hops|
      options[:max_hops] = hops
    end
    
    opts.on("-t", "--timeout SECONDS", Integer, "Timeout for each packet in seconds (default: 2)") do |timeout|
      options[:timeout] = timeout
    end
    
    opts.on("-h", "--help", "Show this help message") do
      puts opts
      exit
    end
  end

  begin
    parser.parse!(ARGV)
    
    if ARGV.empty?
      puts "\e[31m[ERROR] Please specify a destination host or IP address\e[0m"
      puts parser
      exit 1
    end
    
    destination = ARGV[0]
    pulse_check = StabilityCheck.new
    pulse_check.run_full_test(destination, **options)

    sec_check = NetworkSecurity.new
    sec_check.run_full_test(destination)

    
  rescue OptionParser::InvalidOption => e
    puts "[ERROR] #{e.message}"
    puts parser
    exit 1
  rescue Interrupt
    puts "\n\n\e[33m[WARNING] Test interrupted by user\e[0m"
    exit 1
  rescue => e
    puts "\e[31m[ERROR] An error occurred: #{e.message}\e[0m"
    exit 1
  end


  puts "\n\e[36m[INFO] All tests completed!\e[0m"
end

if __FILE__ == $0
  main
end
