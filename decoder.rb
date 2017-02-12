#!/usr/bin/env ruby
# encoding: utf-8

require 'base64'
require 'mcrypt'
require 'digest'

# OnlineTvRecorder
module OnlineTvRecorder
  # OTRKEYFILE
  module OTRKEYFILE
    # Decoder
    class Decoder
      # Hardcoded header decryption key
      HEADER_DECRYPTION_KEY = ['EF3AB29CD19F0CAC5759C7ABD12CC92BA3FE0AFEBF960D63FEBD0F45'].pack('H*')

      # Buffer size for read/write operations
      BUFFER_SIZE = 1 * (1024 * 1024) # 1 MB

      # 10 bytes in input file is the magic number
      FILE_HEADER_MAGIC_KEY_BYTES = 10

      # Input file header data size
      FILE_HEADER_DATA_BYTES = 512

      # All over header size (magic + data)
      FILE_HEADER_BYTES = FILE_HEADER_MAGIC_KEY_BYTES + FILE_HEADER_DATA_BYTES

      # initialize
      #
      # Takes +otrkey_file+ as input OTR file, +email+ and +password+
      def initialize(otrkey_file, email, password)
        @email = email
        @password = Base64.decode64 password

        @file_in_path = otrkey_file
        @file_out_path = File.expand_path(@file_in_path + '/..') + '/my_' + File.basename(@file_in_path, '.otrkey')
      end

      # decrypt_file
      #
      # Decrypts the given input file and writes it to output file
      def decrypt_file(keyphrase)
        # Open input file
        file_in_handle = open_in_file @file_in_path
        file_in_handle.seek FILE_HEADER_BYTES

        # Convert key in binary
        keyphrase_bin = [keyphrase].pack('H*')
        crypto = Mcrypt.new(:'blowfish-compat', :ecb, keyphrase_bin)

        # Open output file and begin with decryption
        file_out_handle = open_out_file @file_out_path
        begin
          while (data = file_in_handle.readpartial(BUFFER_SIZE))
            if data.length < BUFFER_SIZE
              # End of data
              # Write decrypted blocks
              last_block_size = data.length - (data.length % 8)
              file_out_handle.write(crypto.decrypt(data[0...last_block_size]))
              # Write padding unencrypted
              file_out_handle.write(data[last_block_size..-1])
            else
              # Full block read
              file_out_handle.write(crypto.decrypt(data))
            end
          end
        rescue EOFError
          # Okay, read to the end
        ensure
          file_in_handle.close
          file_out_handle.close
        end
      end

      # request_keyphrase -> String
      #
      # Fires decoding request to OTR and returns the key for decryption
      def request_keyphrase
        date = Date.today
        big_key = generate_big_key(date)

        header_hash = get_header
        uri = generate_request(header_hash, big_key, date)
        response = Net::HTTP.get(uri)

        if response.start_with? 'MessageToBePrintedInDecoder'
          # Response error
          raise StandardError.new response[27..-1]
        end

        # Response ok
        response_decoded = Base64.decode64 response
        response_hash = decrypt_response big_key, response_decoded

        # Keyphrase is 'HP'
        response_hash['HP']
      end

      # verify_in_file -> true or false
      #
      # Returns true if input file could be verified successfully
      def verify_in_file
        header_hash = get_header
        verify_file(:IN, header_hash)
      end

      # verify_out_file -> true or false
      #
      # Returns true if output file could be verified successfully
      def verify_out_file
        header_hash = get_header
        verify_file(:OUT, header_hash)
      end

      private
      # verify_file -> true or false
      #
      # Verifies if input or output file matches the provided MD5 Hash
      def verify_file(mode, header_hash)
        # Select mode
        case mode
          when :IN
            hash_hex = header_hash['OH'].dup
            file_handle = open_in_file @file_in_path
            file_handle.seek FILE_HEADER_BYTES
          when :OUT
            hash_hex = header_hash['FH'].dup
            file_handle = open_in_file @file_out_path
          else
            raise StandardError.new 'Unsupported file type. Must be :IN or :OUT'
        end

        # Endianess?
        1.upto(15) do |i|
          hash_hex[2*i] = hash_hex[3*i]
          hash_hex[2*i+1] = hash_hex[3*i+1]
        end
        hash_hex = hash_hex[0..31]

        # Read file and hash it
        md5 = Digest::MD5.new
        begin
          while (data = file_handle.readpartial(BUFFER_SIZE))
            md5 << data
          end
        rescue EOFError
          # Okay, read to the end
        ensure
          file_handle.close
        end
        hash_hex == md5.hexdigest.upcase
      end

      # decrypt_response -> Hash
      #
      # Decrypts the response from OTR and returns the parameters as
      # a Hash.
      def decrypt_response(big_key, response)
        iv_size = Mcrypt.new(:'blowfish-compat', :cbc).iv_size

        crypto = Mcrypt.new(:'blowfish-compat', :cbc, big_key, response[0...iv_size])
        plaintext = crypto.decrypt response[iv_size..-1]

        response_hash = {}
        URI.decode_www_form(plaintext).each { |key_value_array| response_hash[key_value_array[0]] = key_value_array[1] unless key_value_array[0].empty? }
        response_hash
      end

      # generate_request -> URI
      #
      # Generates the uri request to be fired to OTR
      def generate_request(header_hash, big_key, date)
        url_paramters = {
            OS: '01677e4c0ae5468b9b8b823487f14524',
            M: '01677e4c0ae5468b9b8b823487f14524',
            LN: 'DE',
            VN: '1.4.1132',
            IR: 'TRUE',
            IK: 'aFzW1tL7nP9vXd8yUfB5kLoSyATQ',
            FN: header_hash['FN'],
            OH: header_hash['OH'],
            A: @email,
            P: @password
        }

        # Build +code+ parameter inside URI request.
        # D=... is padding used to fill up to 512 bytes
        code = 'FOOOOBAR' + URI.unescape(URI.encode_www_form(url_paramters)) + '&D=' + ('d' * 512)
        # Pick only the first 512 Bytes
        code = code[0...512]

        # Get "random" IV and setup cipher
        iv_size = Mcrypt.new(:'blowfish-compat', :cbc).iv_size
        iv = 'B' * iv_size
        crypto = Mcrypt.new(:'blowfish-compat', :cbc, big_key, iv)
        # Encrypt URI code parameter
        encrypted_code = crypto.encrypt code

        # Finally build the URI
        URI::HTTP.build(
            {
                host: '87.236.198.182',
                path: '/quelle_neu1.php',
                query: URI.encode_www_form(
                    {
                        code: Base64.encode64(encrypted_code),
                        AA: @email,
                        ZZ: date.strftime('%Y%m%d')
                    }.to_a
                )
            }
        )
      end

      # generate_big_key -> String
      #
      # Generates a "big" key (like a hash sum) in a special form
      # to be sent to OTR. Likely used to ensure we wanna request
      # a key for the correct input file
      def generate_big_key(date)
        md5_email = md5_hash @email
        md5_password = md5_hash @password
        date_string = date.strftime '%Y%m%d'

        big_key = ''
        big_key << md5_email[0, 13]
        big_key << date_string[0, 4]
        big_key << md5_password[0, 11]
        big_key << date_string[4, 2]
        big_key << md5_email[21, 11]
        big_key << date_string[6, 2]
        big_key << md5_password[19, 13]
        [big_key].pack('H*')
      end

      # md5_hash -> String
      #
      # Hashes data with MD5 algorithm
      def md5_hash(data)
        md5 = Digest::MD5.new
        md5 << data
        md5.hexdigest
      end

      # get_header -> Hash
      #
      # Reads the header information inside input file header.
      # The first +FILE_HEADER_DATA_BYTES+ contain information
      # encrypted with a fix key +HEADER_DECRYPTION_KEY+.
      # Security by Obscurity warning!
      def get_header
        file_in_handle = open_in_file @file_in_path
        file_in_handle.seek FILE_HEADER_MAGIC_KEY_BYTES
        header_data = file_in_handle.read FILE_HEADER_DATA_BYTES
        file_in_handle.close

        crypto = Mcrypt.new(:'blowfish-compat', :ecb, HEADER_DECRYPTION_KEY)
        plaintext = crypto.decrypt(header_data)

        header_hash = {}
        URI.decode_www_form(plaintext).each { |key_value_array| header_hash[key_value_array[0]] = key_value_array[1] unless key_value_array[0].empty? }
        header_hash
      end

      # open_in_file -> File
      #
      # Opens a file at +filepath+ for reading
      def open_in_file(filepath)
        File.open(filepath, 'rb')
      end

      # open_out_file -> File
      #
      # Opens a file at +filepath+ for writing
      def open_out_file(filepath)
        File.open(filepath, 'wb')
      end

      # check_magic_number -> true or false
      #
      # Reads input file and returns true if magic number
      # begins with 'OTRKEYFILE'
      def check_magic_number
        file_in_handle = open_in_file @file_in_path
        file_in_handle.rewind
        magic_number = file_in_handle.read(FILE_HEADER_MAGIC_KEY_BYTES)
        file_in_handle.close
        magic_number == 'OTRKEYFILE'
      end
    end
  end
end

otrkeyfile_decoder = OnlineTvRecorder::OTRKEYFILE::Decoder.new(ARGV[0], ENV['OTR_EMAIL'], ENV['OTR_PASSWORD'])
puts 'Verifying input file ...'
p otrkeyfile_decoder.verify_in_file

puts 'Query server for keyphrase ...'
keyphrase = otrkeyfile_decoder.request_keyphrase
puts keyphrase

puts 'Decrypt input file...'
p otrkeyfile_decoder.decrypt_file keyphrase

puts 'Verify decrypted file...'
p otrkeyfile_decoder.verify_out_file