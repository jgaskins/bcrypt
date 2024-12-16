require "crypto/bcrypt"
require "crypto/subtle"

# Generate, read and verify `BCrypt` hashes.
#
# NOTE: To use `Password`, you must explicitly import it with `require "crypto/bcrypt/password"`
#
# ```
# require "bcrypt"
#
# password = BCrypt::Password.create("super secret", cost: 10)
# # => $2a$10$rI4xRiuAN2fyiKwynO6PPuorfuoM4L2PVv6hlnVJEmNLjqcibAfHq
#
# password.verify("wrong secret") # => false
# password.verify("super secret") # => true
# ```
#
# See `BCrypt` for hints to select the cost when generating hashes.
module BCrypt
  struct Password
    private SUPPORTED_VERSIONS = ["2", "2a", "2b", "2y"]

    # Hashes a password.
    #
    # ```
    # require "crypto/bcrypt/password"
    #
    # password = BCrypt::Password.create("super secret", cost: 10)
    # # => $2a$10$rI4xRiuAN2fyiKwynO6PPuorfuoM4L2PVv6hlnVJEmNLjqcibAfHq
    # ```
    def self.create(password, cost = Crypto::Bcrypt::DEFAULT_COST) : self
      new(Crypto::Bcrypt.hash_secret(password, cost))
    end

    getter version : String
    getter cost : Int32
    getter salt : Bytes
    getter digest : Bytes

    # Loads a bcrypt hash.
    #
    # ```
    # require "crypto/bcrypt/password"
    #
    # password = BCrypt::Password.new("$2a$10$X6rw/jDiLBuzHV./JjBNXe8/Po4wTL0fhdDNdAdjcKN/Fup8tGCya")
    # password.version # => "2a"
    # password.salt    # => "X6rw/jDiLBuzHV./JjBNXe"
    # password.digest  # => "8/Po4wTL0fhdDNdAdjcKN/Fup8tGCya"
    # ```
    def initialize(@raw_hash : String)
      slice = raw_hash.to_slice
      raise Error.new("Invalid hash string") unless raw_hash.count('$') == 3

      case slice[2]
      when 'a', 'b', 'y'
        version = String.new(slice[1..2])
      when '$'
        version = String.new(slice[1..1])
      else
        version = String.new(slice[1..2])
        raise Error.new("Invalid hash version") unless SUPPORTED_VERSIONS.includes?(version)
      end

      @version = version
      @cost = parse_cost(slice[2 + version.bytesize, 2])
      @salt = slice[5 + version.bytesize, 22]
      @digest = slice[27 + version.bytesize..]

      # raise Error.new("Invalid salt size: #{salt.bytesize}") unless salt.bytesize == 22
      # raise Error.new("Invalid digest size: #{digest.bytesize}") unless digest.bytesize == 31
    end

    # Verifies a password against the hash.
    #
    # ```
    # require "crypto/bcrypt/password"
    #
    # password = BCrypt::Password.create("super secret")
    # password.verify("wrong secret") # => false
    # password.verify("super secret") # => true
    # ```
    def verify(password : String) : Bool
      hashed_password = Crypto::Bcrypt.new(password, String.new(salt), cost)
      hashed_password_digest = Base64.encode(hashed_password.digest)
      Crypto::Subtle.constant_time_compare(String.new(@digest), hashed_password_digest)
    end

    def to_s(io : IO) : Nil
      io << @raw_hash
    end

    def inspect(io : IO) : Nil
      to_s(io)
    end

    # Deserializes a `Password` from a database result row.
    #
    # ```
    # struct User
    #   include DB::Serializable
    #
    #   getter id : UUID
    #   getter email : String
    #   @[DB::Field(converter: BCrypt::Password)]
    #   getter password : BCrypt::Password
    # end
    #
    # user = db.query_one? <<-SQL, email, as: User
    #   SELECT id, email, password
    # SQL
    # ```
    # def self.from_rs(rs : DB::ResultSet)
    #   new rs.read(String)
    # end

    def parse_cost(slice : Bytes)
      cost = 0
      slice.each do |byte|
        cost *= 10
        cost += byte & 0b1111
      end
      raise Error.new("Invalid cost: #{cost}") unless Crypto::Bcrypt::COST_RANGE.includes?(cost)
      cost
    end
  end

  module Base64
    ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    TABLE = Int8[
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, 0, 1, 54, 55,
      56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
      -1, -1, -1, -1, -1, 2, 3, 4, 5, 6,
      7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
      -1, -1, -1, -1, -1, -1, 28, 29, 30,
      31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
      51, 52, 53, -1, -1, -1, -1, -1,
    ]

    def self.encode(d, len = d.size - 1) : String
      off = 0

      String.build do |str|
        loop do
          c1 = d[off] & 0xff
          off += 1
          str << ALPHABET[(c1 >> 2) & 0x3f]
          c1 = (c1 & 0x03) << 4

          if off >= len
            str << ALPHABET[c1 & 0x3f]
            break
          end

          c2 = d[off] & 0xff
          off += 1
          c1 |= (c2 >> 4) & 0x0f
          str << ALPHABET[c1 & 0x3f]
          c1 = (c2 & 0x0f) << 2

          if off >= len
            str << ALPHABET[c1 & 0x3f]
            break
          end

          c2 = d[off] & 0xff
          off += 1
          c1 |= (c2 >> 6) & 0x03
          str << ALPHABET[c1 & 0x3f]
          str << ALPHABET[c2 & 0x3f]

          break if off >= len
        end
      end
    end

    private def self.char64(x)
      TABLE[x.ord]? || -1
    end
  end

  class Error < ::Exception
  end
end
