class Test4MTest < MTest::Unit::TestCase

  SERVER_ADDR = "127.0.0.1:8080"

  def base_url
    "http://#{SERVER_ADDR}"
  end

  def fetch url
    res = HttpRequest.new.get base_url + url
  end

  def test_cgi_priviledge
    res = fetch "/cgi-bin/id.cgi"
    assert_equal "500:500:500", res["body"]
  end
end

status = MTest::Unit.new.run

raise if status.to_i > 0
