require 'rbnacl'
require 'base64'

module ModernSymmetricCipher
  def self.generate_new_key
    # TODO: Return a new key as a Base64 string

    # Generate a new random key for symmetric encryption
    key = RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)

    # Return the key as a Base64 string
    Base64.strict_encode64(key)
  end

  def self.encrypt(document, key)
    # TODO: Return an encrypted string
    #       Use base64 for ciphertext so that it is sendable as text

    # Decode the Base64 key to get the original binary key
    binary_key = Base64.strict_decode64(key)
      
    # Create a new secret box with the key
    secret_box = RbNaCl::SecretBox.new(binary_key)
    
    # Generate a random nonce (should be unique for each encryption)
    nonce = RbNaCl::Random.random_bytes(secret_box.nonce_bytes)
    
    # Encrypt the document with the secret box
    ciphertext = secret_box.encrypt(nonce, document)
    
    # Combine nonce and ciphertext for storage/transmission
    # We need to store the nonce with the ciphertext to decrypt later
    combined = nonce + ciphertext
    
    # Return the combined data as a Base64 string
    Base64.strict_encode64(combined)
  end

  def self.decrypt(encrypted_cc, key)
    # TODO: Decrypt from encrypted message above
    #       Expect Base64 encrypted message and Base64 key

    # Decode the Base64 key and encrypted data
    binary_key = Base64.strict_decode64(key)
    combined = Base64.strict_decode64(encrypted_cc)
    
    # Create a new secret box with the key
    secret_box = RbNaCl::SecretBox.new(binary_key)
    
    # Extract the nonce from the combined data
    # The nonce is the first nonce_bytes of the combined data
    nonce = combined[0, secret_box.nonce_bytes]
    
    # Extract the ciphertext from the combined data
    # The ciphertext is everything after the nonce
    ciphertext = combined[secret_box.nonce_bytes..-1]
    
    # Decrypt the ciphertext using the secret box and nonce
    secret_box.decrypt(nonce, ciphertext)
    
  end
end
