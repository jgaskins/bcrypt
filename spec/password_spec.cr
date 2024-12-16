require "spec"
require "../src/bcrypt"

describe BCrypt::Password do
  describe "new" do
    password = BCrypt::Password.new("$2a$08$K8y0i4Wyqyei3SiGHLEd.OweXJt7sno2HdPVrMvVf06kGgAZvPkga")

    it "parses version" do
      password.version.should eq("2a")
    end

    it "parses cost" do
      password.cost.should eq(8)
    end

    it "parses salt" do
      password.salt.should eq("K8y0i4Wyqyei3SiGHLEd.O".to_slice)
    end

    it "parses digest" do
      password.digest.should eq("weXJt7sno2HdPVrMvVf06kGgAZvPkga".to_slice)
    end

    it "validates the hash string has the required amount of parts" do
      expect_raises(BCrypt::Error, "Invalid hash string") do
        BCrypt::Password.new("blarp")
      end
    end

    it "raises on unsupported version (#11584)" do
      expect_raises(BCrypt::Error, "Invalid hash version") do
        BCrypt::Password.new("$-1$10$blarp")
      end
    end
  end

  describe "create" do
    password = BCrypt::Password.create("super secret", 5)

    it "uses cost" do
      password.cost.should eq(5)
    end

    it "generates salt" do
      password.salt.should_not be_nil
    end

    it "generates digest" do
      password.digest.should_not be_nil
    end
  end

  describe "verify" do
    password = BCrypt::Password.create("secret", 4)
    password2 = BCrypt::Password.new("$2$04$ZsHrsVlj.dsmn74Az1rjmeE/21nYRC0vB5LPjG7ySBfi6lRaO/P22")
    password2a = BCrypt::Password.new("$2a$04$ZsHrsVlj.dsmn74Az1rjmeE/21nYRC0vB5LPjG7ySBfi6lRaO/P22")
    password2b = BCrypt::Password.new("$2b$04$ZsHrsVlj.dsmn74Az1rjmeE/21nYRC0vB5LPjG7ySBfi6lRaO/P22")
    password2y = BCrypt::Password.new("$2y$04$ZsHrsVlj.dsmn74Az1rjmeE/21nYRC0vB5LPjG7ySBfi6lRaO/P22")

    it "verifies password is incorrect" do
      (password.verify "wrong").should be_false
    end

    it "verifies password is correct" do
      (password.verify "secret").should be_true
    end

    it "verifies password version 2 is correct (#11584)" do
      (password2.verify "secret").should be_true
    end
    it "verifies password version 2a is correct (#11584)" do
      (password2a.verify "secret").should be_true
    end
    it "verifies password version 2b is correct (#11584)" do
      (password2b.verify "secret").should be_true
    end
    it "verifies password version 2y is correct" do
      (password2y.verify "secret").should be_true
    end
  end

  describe "==" do
    it "returns true for two of the same password" do
      first = BCrypt::Password.new("$2a$04$6cfW6PO4vAhaExO4q9sR2.VOm2L9GufVrX1wye9zNg3ktCW5QRAH2")
      second = BCrypt::Password.new("$2a$04$6cfW6PO4vAhaExO4q9sR2.VOm2L9GufVrX1wye9zNg3ktCW5QRAH2")

      first.should eq second
    end

    it "returns false for two different passwords" do
      first = BCrypt::Password.new("$2a$04$6cfW6PO4vAhaExO4q9sR2.VOm2L9GufVrX1wye9zNg3ktCW5QRAH2")
      second = BCrypt::Password.new("$2a$04$PbS16SDniZkEjMVmuu0KCezHX5PR1tR17zUrDG11q64OS2g3Qfnpq")

      first.should_not eq second
    end
  end
end
