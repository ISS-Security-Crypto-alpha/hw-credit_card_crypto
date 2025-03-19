# frozen_string_literal: true

require_relative '../credit_card'
require_relative '../substitution_cipher'
require_relative '../double_trans_cipher'
require_relative '../sk_cipher'
require 'minitest/autorun'
require 'minitest/rg'

keys = 5.times.collect { ModernSymmetricCipher.generate_new_key }

describe 'Test card info encryption' do
  before do
    @cc = CreditCard.new('4916603231464963', 'Mar-30-2020',
                         'Soumya Ray', 'Visa')
    @key = 3
  end

  describe 'Using Caesar cipher' do
    it 'HAPPY: should encrypt card information' do
      enc = SubstitutionCipher::Caesar.encrypt(@cc, @key)
      _(enc).wont_equal @cc.to_s
      _(enc).wont_be_nil
    end

    it 'HAPPY: should decrypt text' do
      enc = SubstitutionCipher::Caesar.encrypt(@cc, @key)
      dec = SubstitutionCipher::Caesar.decrypt(enc, @key)
      _(dec).must_equal @cc.to_s
    end
  end

  describe 'Using Permutation cipher' do
    it 'HAPPY: should encrypt card information' do
      enc = SubstitutionCipher::Permutation.encrypt(@cc, @key)
      _(enc).wont_equal @cc.to_s
      _(enc).wont_be_nil
    end

    it 'HAPPY: should decrypt text' do
      enc = SubstitutionCipher::Permutation.encrypt(@cc, @key)
      dec = SubstitutionCipher::Permutation.decrypt(enc, @key)
      _(dec).must_equal @cc.to_s
    end
  end

  # TODO: Add tests for double transposition and modern symmetric key ciphers
  #       Can you DRY out the tests using metaprogramming? (see lecture slide)
  describe 'Using Double Transposition cipher' do
    it 'HAPPY: should encrypt card information' do
      enc = DoubleTranspositionCipher.encrypt(@cc.to_s, @key)
      _(enc).wont_equal @cc.to_s
      _(enc).wont_be_nil
    end

    it 'HAPPY: should decrypt text' do
      enc = DoubleTranspositionCipher.encrypt(@cc.to_s, @key)
      dec = DoubleTranspositionCipher.decrypt(enc, @key)
      _(dec).must_equal @cc.to_s
    end
  end

  describe 'Using Modern Symmetric cipher' do
    keys.each do |key|
      it 'HAPPY: should encrypt and decrypt card information' do
        enc = ModernSymmetricCipher.encrypt(@cc.to_s, key)
        dec = ModernSymmetricCipher.decrypt(enc, key)
        _(enc).wont_equal @cc.to_s
        _(enc).wont_be_nil
        _(dec).must_equal @cc.to_s
      end

      it 'SAD: should gracefully fail for altered encrypted message' do
        enc = ModernSymmetricCipher.encrypt(@cc.to_s, key)
        enc[-1] = 'x'
        _ { ModernSymmetricCipher.decrypt(enc, key) }.must_raise RbNaCl::CryptoError
      end
    end
  end
end
