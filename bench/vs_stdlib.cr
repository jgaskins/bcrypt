require "benchmark"
require "crypto/bcrypt/password"
require "../src/bcrypt"

hash = "$2a$04$6cfW6PO4vAhaExO4q9sR2.VOm2L9GufVrX1wye9zNg3ktCW5QRAH2"
shard = nil
stdlib = nil

Benchmark.ips do |x|
  x.report "BCrypt::Password.new" { shard = BCrypt::Password.new(hash) }
  x.report "Crypto::Bcrypt::Password.new" { stdlib = Crypto::Bcrypt::Password.new(hash) }
end

puts
puts shard
puts stdlib
