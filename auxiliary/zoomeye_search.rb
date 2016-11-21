##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'net/https'
require 'uri'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Zoomeye Search',
                      'Description' => %q{
                          利用 Zoomeye 搜索,获取主机IP
                      },
                      'Author' =>
                          [
                              '扶摇直上打飞机',
                          ],
                      'License' => MSF_LICENSE,
          )
    )

    deregister_options('RHOST', 'DOMAIN', 'SSL', 'DigestAuthIIS', 'NTLM::SendLM',
                       'NTLM::SendNTLM', 'VHOST', 'RPORT', 'NTLM::SendSPN', 'NTLM::UseLMKey',
                       'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')

    register_options(
        [
            OptString.new('Zoomeye_Username', [true, 'The Zoomeye Username']),
            OptString.new('Zoomeye_Password', [true, 'The Zoomeye Password']),
            OptString.new('QUERY', [true, 'Keywords you want to search for']),
            OptString.new('OUTFILE', [false, 'A filename to store the list of IPs']),
            OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        ], self.class)
  end


  def get_accesskey
    res = send_request_raw({
                               'method' => 'POST',
                               'rhost' => 'api.zoomeye.org',
                               'SSL' => true,
                               'uri' => '/user/login',
                               'rport' => 443,
                               'data' => "{\"username\": \"" + username + "\",\"password\": \"" + passwd + "\"}",
                           })
    if res.code.to_s == '200'
      json = JSON.parse(res.body)
      accesskey = json['access_token']
      return accesskey
    else
      fail_with(Failure::BadConfig, '401 Unauthorized. Your Zoomeye_Account is invalid')
    end
  end

  def zoomeye_query(page)
    res = send_request_cgi({
                               'method' => 'GET',
                               'rhost' => 'api.zoomeye.org',
                               'SSL' => true,
                               'uri' => '/host/search',
                               'rport' => 443,
                               'headers' =>
                                   {
                                       'Authorization' => "JWT " + get_accesskey
                                   },
                               'vars_get' =>
                                   {
                                       'query' => query,
                                       'page' => page,
                                   }
                           })
    if res.code.to_s == '200'

      json = JSON.parse(res.body)
      for host in json['matches'] do
        @hosts.push(host['ip'])
      end

    else
      fail_with(Failure::BadConfig, '401 Unauthorized. Your Zoomeye_Account is invalid')
    end
  end

  # save output to file
  def save_output
    File.open(outfile, 'wb') do |f|
      @hosts.each{|host| f.write(host + "\n")}
      print_status("Saved results in #{outfile}")
    end
  end

  def run
    @hosts = Array.new
    for page in 1..maxpage
      zoomeye_query(page)
    end

    save_output if outfile
    @hosts.each{|host| print_good(host)}
  end

  def username
    datastore['Zoomeye_Username']
  end

  def passwd
    datastore['Zoomeye_Password']
  end

  def query
    datastore['QUERY']
  end

  def maxpage
    datastore['MAXPAGE']
  end

  def outfile
    datastore['OUTFILE']
  end
end