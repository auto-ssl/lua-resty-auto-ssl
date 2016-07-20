package AutoSsl;
use strict;
use warnings;
use Cwd qw(cwd);
use Expect;
use File::Find qw(finddepth);
use File::Spec::Functions qw(canonpath);

sub setup {
  our $CWD = cwd();

  our $ngrok = Expect->spawn("./t/vendor/ngrok-2.0.25/ngrok http 9080 --log stdout --log-format logfmt --log-level debug");
  $ngrok->log_stdout(0);
  $ngrok->expect(10, "-re", "Hostname:([a-z0-9]+.ngrok.io)") or die "failed to find hostname for ngrok";
  $ENV{TEST_NGINX_NGROK_HOSTNAME} = ($ngrok->matchlist())[0] or die "failed to extract hostname for ngrok";
  $ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR} ||= "/tmp/resty-auto-ssl-test";
  $ENV{TEST_NGINX_RESOLVER} ||= "8.8.8.8 8.8.4.4";

  # If the tests have previously been run, wipe out any test data, but ensure we
  # retain the private account key registered with Let's Encrypt. If we don't,
  # Let's Encrypt's staging environment still has limits on this initial account
  # registration, so you can end up blocked due to repeated registrations.
  if(-d $ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}) {
    finddepth(\&wanted, $ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR});
    sub wanted {
      my $find_path = canonpath($File::Find::name);
      my $keep_private_key_pem_path = canonpath("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/letsencrypt/private_key.pem");
      my $keep_private_key_json_path = canonpath("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/letsencrypt/private_key.json");

      if(index($keep_private_key_pem_path, $find_path) == -1 && index($keep_private_key_json_path, $find_path) == -1) {
        if(-d $find_path) {
          rmdir $find_path;
        } else {
          unlink $find_path;
        }
      }
    }
  }
}

1;
