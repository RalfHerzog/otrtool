#!/usr/bin/env ruby
# encoding: utf-8

require 'openssl'

class BlowFish < Struct.new(:key, :pad_with_spaces)
  def encrypt(str)
    cipher = OpenSSL::Cipher::BF.new(:ECB).encrypt
    if pad_with_spaces
      str += " " until str.bytesize % 8 == 0
      cipher.padding = 0
    end
    cipher.key = key
    binary_data = cipher.update(str) << cipher.final
    hex_encoded = binary_data.unpack('H*').first
  end

  def decrypt(hex_encoded)
    cipher = OpenSSL::Cipher.new('bf-ecb').decrypt
    cipher.padding = 0 if pad_with_spaces
    cipher.key = key
    binary_data = [hex_encoded].pack('H*')
    str = cipher.update(binary_data) << cipher.final
    str.force_encoding(Encoding::UTF_8)
    str
  end
end

# Choose the encryption key. Its length must be a multiple of  8 and no longer than 56
bf = BlowFish.new("x"*56, true)

sentence = ARGV[0] || "foo bar foo bar foo bar foo bar foo bar foo bar baz"
encrypted = bf.encrypt(sentence)
puts encrypted.length
puts sentence.inspect
puts "Encrypt: #{encrypted}"
puts "Decoded: #{bf.decrypt encrypted}"