package AutoSsl;
use strict;
use warnings;
use Cwd qw(abs_path);
use Expect;
use File::Basename;
use File::Find qw(finddepth);
use File::Spec::Functions qw(canonpath);
use File::stat;

sub setup {
  our $ngrok = Expect->spawn("ngrok http 9080 --log stdout --log-format logfmt --log-level debug") or die "failed to spawn ngrok: $!";
  $ngrok->log_stdout(0);
  $ngrok->expect(10, "-re", "Hostname:([a-z0-9]+.ngrok.io)") or die "failed to find hostname for ngrok";
  $ENV{TEST_NGINX_ROOT_DIR} ||= dirname(dirname(dirname(abs_path(__FILE__))));
  $ENV{TEST_NGINX_NGROK_HOSTNAME} = ($ngrok->matchlist())[0] or die "failed to extract hostname for ngrok";
  $ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR} ||= "/tmp/resty-auto-ssl-test";
  $ENV{TEST_NGINX_RESOLVER} ||= "8.8.8.8 8.8.4.4";

  # If the tests have previously been run, wipe out any test data.
  if(-d $ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}) {
    # Keep existing account keys registered with Let's Encrypt for about 1 day.
    # This prevents us from running into Let's Encrypt's account registration
    # rate limits (that are still low enough in the Let's Encrypt staging
    # environment that we can hit these on staging).
    #
    # But still re-register once a day to deal with issues like new license
    # terms, where old accounts may behave differently than new accounts
    # (https://community.letsencrypt.org/t/lets-encrypt-subscriber-agreement-v1-1-1/17409/7).
    my $existing_accounts_path = canonpath("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/letsencrypt/accounts");
    my $keep_existing_accounts = 0;
    if(-d $existing_accounts_path) {
      my $current_time = time;
      my $account_time = stat($existing_accounts_path)->mtime;
      my $time_diff = 60 * 60 * 23; # 23 hours
      if($current_time - $account_time < $time_diff) {
        $keep_existing_accounts = 1;
      }
    }

    my $wanted = sub {
      my $find_path = canonpath($File::Find::name);
      my $delete = 1;

      # Keep recent account files.
      if($keep_existing_accounts) {
        if(index($existing_accounts_path, $find_path) != -1 || index($find_path, $existing_accounts_path) != -1) {
          $delete = 0;
        }
      }

      # Always keep the root directory for the "worker-perms" test, so we
      # retain the special permissions created on this by sudo in the Makefile.
      if($find_path eq "/tmp/resty-auto-ssl-test-worker-perms") {
        $delete = 0;
      }

      if($delete) {
        if(-d $find_path) {
          rmdir $find_path;
        } else {
          unlink $find_path;
        }
      }
    };
    finddepth(\&$wanted, $ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR});
  }
}

1;
