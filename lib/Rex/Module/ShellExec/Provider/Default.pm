use strict;
use warnings;

package Rex::Module::ShellExec::Provider::Default;

use Rex -minimal;
use Rex::Helper::Run;
use Rex::Commands::Fs;
use Rex::Commands::File;

use boolean;
use Carp;

sub new {
    my $that  = shift;
    my $proto = ref($that) || $that;
    my $self  = {@_};

    bless( $self, $proto );

    return $self;
}

sub _run {
    my ($self, @params) = @_;

    if ( $Rex::Module::ShellExec::MOCK_RUN ) {
        Rex::Logger::info("ShellExec: run: $params[0]");
    } else  {
        i_run @params;
    }
}

sub execute {
    my ($self, $rule_config) = @_;

    my (@cmd_lines, @only_if_lines, @unless_lines);
    my $changed = 0;

    my %cmd_opts = ();

    if ( $rule_config->{only_if} && $rule_config->{unless} ) {
        confess "You defined only_if and unless. But only one can be used.";
    }

    if ( $rule_config->{cwd} ) {
        $cmd_opts{cwd} = $rule_config->{cwd};
    }

    if ( $rule_config->{env} ) {
        $cmd_opts{env} = $rule_config->{env};
    }

    if ( $rule_config->{timeout} ) {
        $cmd_opts{timeout} = $rule_config->{timeout};
    }

    if ( $rule_config->{creates} && is_file( $rule_config->{creates} ) ) {
        # file exists, so command already ran
        return 0;
    }

    if ( $rule_config->{command} ) {
        @cmd_lines = split(/\n/, $rule_config->{command});
        if($cmd_lines[0] !~ m/^#!\//) {
            # shebang not there, so add /bin/bash for default
            unshift(@cmd_lines, "#!" . $rule_config->{interpreter});
        }
    }

    if ( $rule_config->{only_if} ) {
        @only_if_lines = split(/\n/, $rule_config->{only_if});
        if($only_if_lines[0] !~ m/^#!\//) {
            # shebang not there, so add /bin/bash for default
            unshift(@only_if_lines, "#!" . $rule_config->{interpreter});
        }
    }

    if ( $rule_config->{unless} ) {
        @unless_lines = split(/\n/, $rule_config->{unless});
        if($unless_lines[0] !~ m/^#!\//) {
            # shebang not there, so add /bin/bash for default
            unshift(@unless_lines, "#!" . $rule_config->{interpreter});
        }
    }

    my ($unless_file, $only_if_file, $cmd_file);
    if ( @cmd_lines ) {
        $cmd_file = "/tmp/" . get_random(8, 'a' .. 'z') . ".tmp";
        file $cmd_file,
            content => join("\n", @cmd_lines),
            mode => 755;
    } else {
        die "No command defined.";
    }

    if ( @unless_lines ) {
        $unless_file = "/tmp/" . get_random(8, 'a' .. 'z') . ".tmp";
        file $unless_file,
            content => join("\n", @unless_lines),
            mode => 755;
    }

    if ( @only_if_lines ) {
        $only_if_file = "/tmp/" . get_random(8, 'a' .. 'z') . ".tmp";
        file $only_if_file,
            content => join("\n", @only_if_lines),
            mode => 755;
    }

    if ( @unless_lines ) {
        $self->_run($unless_file, fail_ok => true);
        my $unless_chk = $?;

        if ( $unless_chk ) {
            $self->_run($cmd_file, %cmd_opts);
            $changed = 1;
        }
    }

    elsif ( @only_if_lines ) {
        $self->_run($only_if_file, fail_ok => true);
        my $only_if_chk = $? == 0 ? 1 : 0;

        if ( $only_if_chk ) {
            $self->_run($cmd_file, %cmd_opts);
            $changed = 1;
        }
    }

    else {
        $self->_run($cmd_file, %cmd_opts, fail_ok => true);
        $changed = 1;
    }

    my $ret = $?;

    unlink $unless_file if $unless_file;
    unlink $only_if_file if $only_if_file;
    unlink $cmd_file;

    if ( $rule_config->{auto_die} && $ret != 0 ) {
        confess "Error executing command.";
    }

    return $changed;
}

1;