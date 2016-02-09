use Cwd qw(cwd);
use Expect;
use File::Path qw(make_path remove_tree);
use File::Slurp qw(read_file write_file);

our $CWD = cwd();

our $ngrok = Expect->spawn("./t/vendor/ngrok-2.0.19/ngrok http 9080 --log stdout --log-format logfmt --log-level debug");
$ngrok->log_stdout(0);
$ngrok->expect(10, "-re", "Hostname:([a-z0-9]+.ngrok.io)") or die "failed to find hostname for ngrok";
$ENV{TEST_NGINX_NGROK_HOSTNAME} = ($ngrok->matchlist())[0] or die "failed to extract hostname for ngrok";

$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR} = "/tmp/resty-auto-ssl-test";
my $letsencrypt_key = read_file("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/letsencrypt/private_key.pem", err_mode => "quiet");
remove_tree($ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR});

if($letsencrypt_key) {
  make_path("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/letsencrypt");
  write_file("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/letsencrypt/private_key.pem", $letsencrypt_key);
}

$ENV{TEST_NGINX_LUA_PACKAGE_PATH} = "$::CWD/lib/?.lua;;";
