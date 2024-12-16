require "db"

require "./bcrypt"

# :nodoc:
class DB::ResultSet
  def read(password : BCrypt::Password.class)
    password.new read(String)
  end
end
