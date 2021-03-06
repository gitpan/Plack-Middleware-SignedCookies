
# This file was automatically generated by Dist::Zilla::Plugin::MakeMaker v5.029.
use strict;
use warnings;

use 5.010;

use ExtUtils::MakeMaker;



my %WriteMakefileArgs = (
  "ABSTRACT" => "accept only server-minted cookies",
  "AUTHOR" => "Aristotle Pagaltzis <pagaltzis\@gmx.de>",
  "CONFIGURE_REQUIRES" => {
    "ExtUtils::MakeMaker" => 0
  },
  "DISTNAME" => "Plack-Middleware-SignedCookies",
  "EXE_FILES" => [],
  "LICENSE" => "perl",
  "MIN_PERL_VERSION" => "5.010",
  "NAME" => "Plack::Middleware::SignedCookies",
  "PREREQ_PM" => {
    "Digest::SHA" => 0,
    "Plack::Middleware" => 0,
    "Plack::Util" => 0,
    "Plack::Util::Accessor" => 0,
    "parent" => 0,
    "strict" => 0,
    "warnings" => 0
  },
  "TEST_REQUIRES" => {
    "File::Find" => 0,
    "File::Temp" => 0,
    "HTTP::Request::Common" => 0,
    "Plack::Builder" => 0,
    "Plack::Request" => 0,
    "Plack::Test" => 0,
    "Test::More" => 0
  },
  "VERSION" => "1.102",
  "test" => {
    "TESTS" => "t/*.t"
  }
);


my %FallbackPrereqs = (
  "Digest::SHA" => 0,
  "ExtUtils::MakeMaker" => 0,
  "File::Find" => 0,
  "File::Temp" => 0,
  "HTTP::Request::Common" => 0,
  "Plack::Builder" => 0,
  "Plack::Middleware" => 0,
  "Plack::Request" => 0,
  "Plack::Test" => 0,
  "Plack::Util" => 0,
  "Plack::Util::Accessor" => 0,
  "Test::More" => 0,
  "parent" => 0,
  "strict" => 0,
  "warnings" => 0
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.63_03) } ) {
  delete $WriteMakefileArgs{TEST_REQUIRES};
  delete $WriteMakefileArgs{BUILD_REQUIRES};
  $WriteMakefileArgs{PREREQ_PM} = \%FallbackPrereqs;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



