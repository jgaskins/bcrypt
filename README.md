# `BCrypt::Password`

bcrypt password objects using the `bcrypt` algorithm via Crystal's `Crypto::Bcrypt`.

This project exists due to Crystal proposing [the removal of `Crypto::Bcrypt::Password`](https://github.com/crystal-lang/crystal/issues/15276). All code is ported from Crystal's stdlib [`Crypto::Bcrypt::Password`](https://github.com/crystal-lang/crystal/blob/dacd97bcc/src/crypto/bcrypt/password.cr).

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     bcrypt:
       github: jgaskins/bcrypt
   ```

2. Run `shards install`

## Usage

First, require this shard:

```crystal
require "bcrypt"
```

### Hashing a password

To hash a password, use the `BCrypt::Password.create` method, which will return a `BCrypt::Password` instance:

```crystal
password = BCrypt::Password.create("password")
```

You can also specify the "cost" of the hash when you create it.

```crystal
password = BCrypt::Password.create("password", cost: 12)
```

You can use the `BCrypt::Password#to_s` method to get a string from that object.

### Verifying a password

To verify a cleartext password, use the `verify` method:

```crystal
password.verify("password") # => true
password.verify("wrong-pw") # => false
```

### Instantiation

If you have a pre-hashed password string, you can pass it to `BCrypt::Password.new`.

```crystal
password = BCrypt::Password.new(hashed_password)
```

You can also require the `bcrypt/db` extension to allow `BCrypt::Password` objects to be parsed directly from a database query:

```crystal
require "pg"

pg = DB.open("postgres:///")

struct User
  include DB::Serializable

  getter id : UUID
  getter email : String
  getter password : BCrypt::Password
end

user = pg.query_one "SELECT id, email, password FROM users WHERE id = $1", id, as: User

pp user.password.verify("password")
```

`BCrypt::Password` parses hashed passwords 6.6x as fast as `Crypto::Bcrypt::Password`:

```
crystal run --release bench/vs_stdlib.cr
        BCrypt::Password.new  45.20M ( 22.12ns) (± 1.73%)  16.0B/op        fastest
Crypto::Bcrypt::Password.new   6.83M (146.49ns) (± 2.88%)   400B/op   6.62× slower
```

## Contributing

1. Fork it (<https://github.com/jgaskins/bcrypt/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Jamie Gaskins](https://github.com/jgaskins) - creator and maintainer
