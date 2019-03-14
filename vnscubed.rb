#!/usr/bin/env ruby
#
# Copyright (c) 2010-2016, Cohesive Flexible Technologies, Inc.
#
# This copyrighted material is the property of
# Cohesive Flexible Technologies and is subject to the license
# terms of the product it is contained within, whether in text
# or compiled form.  It is licensed under the terms expressed
# in the accompanying README and LICENSE files.
#
# This program is AS IS and  WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
#

$:.unshift File.dirname(__FILE__)

require 'getoptlong'
require 'api'
require 'yaml'

module VNS3; module API
  class CLI

    def initialize
      @host = ENV["VNS3_HOST"] || 'localhost'
      @port = ENV["VNS3_PORT"] ? ENV["VNS3_PORT"].to_i : 8000
      @apikey = ENV["VNS3_KEY"] || 'api'
      @apisecret = ENV["VNS3_SECRET"]
      @apikey_file = ENV["VNS3_KEY_FILE"]
      @apisecret_file = ENV["VNS3_SECRET_FILE"]
      @output_format = ENV["VNS3_FORMAT"] || 'YAML'
      @output = nil
      @timeout = 10.0
    end

    def error(msg)
      $stderr.write "Error: #{msg.chomp}\n(use --help for help)\n"
      exit 1
    end

    def run!
      begin
        parse_command_line
      rescue => e
        error e.message
      end

      case @method
        when :list
          puts VNS3::API.api_methods.map { |m| m.to_s
            }.sort.join("\n")
          exit 0
        when :help
          exit show_help
        else
          error("method not found - #{@method}") unless
            VNS3::API.api_methods.include?(@method)
      end

      begin
        send_request
      rescue VNS3::API::APIError => e
        if @conn.error
          n = @conn.error['name'] rescue 'UnknownError'
          m = @conn.error['message'] rescue ''
          n += ": #{m}" if m
          n += "\ntech support ref. #{@conn.error['log']}\n" if
            @conn.error['log']
        else
          n = "#{e.class}: #{e.message}"
        end
        error n
      rescue Exception => e
        error "#{e.class.name} #{e.message}"
      rescue => e
        error "#{e.class.name} #{e.message}"
      end

      final_output
    end

    def send_request
      @conn = VNS3::API::Connection.new(@host, :port => @port,
                :key => @apikey, :secret => @apisecret, :timeout => @timeout)
      @resp = @conn.send(@method, @method_args)
    end

    def final_output
      if @output
        out = File.open(@output, "wb")
      else
        out = $stdout
      end

      if @output_format == "JSON"
        out.write(@resp.to_json)
      else
        # YAML as pretty print format for now
        if @resp.is_a?(Array) || @resp.is_a?(Hash)
          out.write(@resp.to_yaml)
        else
          out.write(@resp)
        end
      end

      if @output
        out.close
      else
        puts
      end

      true
    end

    def parse_command_line
      opts = GetoptLong.new(*(standard_options + method_options))
      @method_args = { }

      opts.each do |opt, arg|
        case opt
          when "--host"
            @host = arg
          when "--port"
            @port = arg.to_i
          when "--apikey"
            @apikey = arg
          when "--apikey-file"
            File.open(arg) { |f| @apikey = f.read }
          when "--apisecret"
            @apisecret = arg
          when "--apisecret-file"
            File.open(arg) { |f| @apisecret = f.read }
          when "--output"
            @output = arg
          when "--output-format"
            @output_format = arg
          when "--timeout"
            @timeout = arg.to_f
          when "--help"
            @help = true
          else
              name = opt[2..-1].gsub(/-/, '_').to_sym # "--foo" => :foo
              unless VNS3::API.blob_args.include? name
                @method_args[name] = arg
              else
                # read blob value from file or $stdin
                if arg == '-'
                  @method_args[name] = $stdin.read
                else
                  File.open(arg, 'rb') { |f| @method_args[name] = f.read }
                end
              end
          end
        end

        if ARGV.empty?
          exit(show_help) if @help
          raise("command missing")
        end
        raise "too many commands" if ARGV.size > 1

        @method = ARGV[0].to_sym

        return @method if [:list, :help].include? @method

        meth = VNS3::API::describe_api_method(@method)
        raise "API method not found" unless meth

        if @help
          if meth[:args] && meth[:args].any?
            puts "Arguments for #{@method}: #{meth[:args].inspect}"
          else
            puts "Arguments for #{@method}: none"
          end
          exit 0
        end

        if meth[:binary_response]
          raise("expecting binary response - must use -o") if @output.nil?
        end

        @method
    end

    def options_with_help_messages
      @options_with_help_messages ||= [
          [ "--host",        "-H", GetoptLong::REQUIRED_ARGUMENT,
            "Name or address of VNS3 Controller. env:VNS3_HOST" ],
          [ "--port",        "-P", GetoptLong::REQUIRED_ARGUMENT,
            "Port of VNS3 Controller. env:VNS3_PORT" +
            "\n\t\t\t(default: 8000)" ],
          [ "--apikey",         "-K", GetoptLong::REQUIRED_ARGUMENT,
            "API key. env:VNS3_KEY" ],
          [ "--apikey-file",    "-Y", GetoptLong::REQUIRED_ARGUMENT,
            "Read API key from file. env:VNS3_KEY_FILE"],
          [ "--apisecret",      "-S", GetoptLong::REQUIRED_ARGUMENT,
            "API secret. env:VNS3_SECRET" ],
          [ "--apisecret-file", "-C", GetoptLong::REQUIRED_ARGUMENT,
            "Read API secret from file. env:VNS3_SECRET_FILE" ],
          [ "--output",      "-o", GetoptLong::REQUIRED_ARGUMENT,
            "Write to a file instead of stdout" ],
          [ "--output-format",      "-f", GetoptLong::REQUIRED_ARGUMENT,
            "Output format, JSON or YAML" +
            "\n\t\t\t(default: YAML)" ],
          [ "--help",        "-h", GetoptLong::NO_ARGUMENT,
            "Show help"]
      ]
    end

    def standard_options
      @standard_options ||= options_with_help_messages.map { |r| r[0...-1] }
    end

    def method_options
      return @method_options if @method_options

      keys = VNS3::API.api_methods.map { |meth|
               VNS3::API.describe_api_method(meth)
               }.map { |ahash| ahash[:args].keys unless ahash[:args].nil?
               }.flatten.uniq.reject { |k| k.nil? }
      @method_options = [ ]
      keys.map { |k|
        if k.to_s.include? '_'
          @method_options <<
            [ "--#{k.to_s.gsub(/_/, '-')}", GetoptLong::REQUIRED_ARGUMENT ]
        end
        @method_options << [ "--#{k}", GetoptLong::REQUIRED_ARGUMENT ]
      }
      @method_options
    end

    def show_help
      puts "Usage: #{File.basename($0)} [options] command"
      puts
      puts "Options:"
      options_with_help_messages.each do |o|
        puts " %-15s\t#{o.last}" % "#{o[0]} (#{o[1]})"
      end
      puts
      puts "Commands:"
      puts " list - list all available commands"
      puts
      true
    end

  end
end
end

app = VNS3::API::CLI.new
app.run!

__END__

