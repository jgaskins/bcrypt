require "./spec_helper"
require "../src/db"

require "pg"

pg = DB.open("postgres:///")

struct User
  include DB::Serializable

  getter id : UUID
  getter email : String
  getter password : BCrypt::Password
end

describe "deserializing from a DB::ResultSet" do
  it "parses from a row" do
    password = BCrypt::Password.create("password", cost: 4)
    user = pg.query_one "SELECT gen_random_uuid() id, 'user@example.com' email, $1 password", password, as: User

    password.verify("password").should eq true
  end
end
