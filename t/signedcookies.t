use strict;
no warnings;
use Plack::Test;
use Plack::Builder;
use Test::More;
use HTTP::Request::Common;
use Plack::Middleware::SignedCookies ();
use Plack::Request ();

my $mw = Plack::Middleware::SignedCookies->new( app => sub {
	my $req = Plack::Request->new( shift );
	my $res = $req->new_response( 200 );
	my $c = $req->cookies // {};
	$res->body( join '!', map {; $_, $c->{$_} } sort keys %$c );
	$res->cookies->{'1foo'} = 'lorem ipsum';
	$res->cookies->{'2bar'} = 'dolor sit amet';
	return $res->finalize;
} );

test_psgi app => $mw->to_app, client => sub {
	my $cb = shift;
	my $res;

	$res = $cb->( GET 'http://localhost/', Cookie => '1foo=1' );
	is $res->content, '', 'Unknown cookies ignored in initial request';

	my ( $junk, @c ) = 0;
	$res->headers->scan( sub {
		return unless 'set-cookie' eq lc $_[0];
		my ( $kv ) = split /;\s*/, $_[1], 2;
		++$junk, return if $kv !~ /\A(1foo=|2bar=)/;
		push @c, $kv;
	} );
	is 0+@c,  2, 'Initial response includes the expected cookies';
	is $junk, 0, '... and no unexpected ones';

	$res = $cb->( GET 'http://localhost/', Cookie => join '; ', @c );
	is $res->content, '1foo!lorem ipsum!2bar!dolor sit amet', 'Own cookies are recognized';

	$res = $cb->( GET 'http://localhost/', Cookie => join '; ', '2bar=1', grep { !/^2bar=/ } @c );
	is $res->content, '1foo!lorem ipsum', 'Tampered cookies are rejected';
};

done_testing;
