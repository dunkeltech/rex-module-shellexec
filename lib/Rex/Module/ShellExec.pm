use strict;
use warnings;
package Rex::Module::ShellExec;

use Rex -minimal;
use Rex::Resource::Common;
use Rex::Commands::Gather;

use Carp;
use boolean;

my $__provider = {
    default => "Rex::Module::ShellExec::Provider::Default"
};

our $MOCK_RUN = 0;

resource "shell_exec", { export => 1 }, sub {
   my $resource_name = resource_name;

   my $rule_config = {
      cwd => param_lookup( "cwd", undef ),
      only_if => param_lookup( "only_if", undef ),
      unless => param_lookup( "unless", undef ),
      env => param_lookup( "env", undef ),
      timeout => param_lookup( "timeout", undef ),
      auto_die => param_lookup( "auto_die", true ),
      command => param_lookup( "command", undef ),
      creates => param_lookup( "creates", undef ),
      interpreter => param_lookup( "interpreter", "/bin/bash" ),
      name => $resource_name,
   };

   my $provider =
      param_lookup( "provider", case ( lc(operating_system), $__provider ) );

   $provider->require;

   my $provider_o = $provider->new();

   my $changed = $provider->execute($rule_config);

   if ( $changed ) {
      emit created, "ShellExec command $resource_name created.";
   }
};

1;

=pod

=head1 NAME

Rex::Misc::ShellBlock - Module to execute a shell block.

=head1 DESCRIPTION

This module exports a function called I<shell_block>. This function will upload your shell script to the remote system and executes it. Returning its output as a string.


=head1 EXPORTED FUNCTIONS

=over 4

=item shell_block($code)

This function will add a default shebang of '#!/bin/bash' to your code if no shebang is found and return its output.

 my $ret = shell_block <<EOF;
 echo "hi"
 EOF


=item shell_block($shebang, $code)

This function will add $shebang to your code and return its output.

 my $ret = shell_block "/bin/sh", <<EOF;
 echo "hi"
 EOF

=back

=head1 USAGE

 use Rex::Misc::ShellBlock;
    
 task "myexec", sub {
    shell_block <<EOF;
 echo "hi"
 EOF
  
 };

