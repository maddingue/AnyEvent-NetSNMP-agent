package AnyEvent::NetSNMP::agent;

use strict;
use warnings;

use AnyEvent;
use Carp;
use NetSNMP::agent;
use SNMP ();
use SNMP::ToolBox;


our $VERSION = "0.000";


use constant {
    TYPE            => 0,
    VALUE           => 1,

    HAVE_SORT_KEY_OID
                    => eval "use Sort::Key::OID 0.04 'oidsort'; 1" ? 1 : 0,
};



#
# new()
# ---
sub new {
    my $class = shift;
    croak "error: odd number of arguments" unless @_ % 2 == 0;

    my %args = (
        # defaults
        Name    => "perl",
        AgentX  => 0,
        Ping    => 10,

        # given args
        @_,
    );

    # create the NetSNMP sub-agent
    my %opts = (
        Name    => $args{Name},
        AgentX  => $args{AgentX},
       (Ports   => $args{Ports})x!! defined $args{Ports},
    );

    my $agent = NetSNMP::agent->new(%opts);

    # construct the object
    my @watchers;
    my %attr = (
        args        => \%args,
        _watchers   => \@watchers,
        agent       => $agent,
        oid_tree    => {},
        oid_list    => [],
    );
    my $self = bless \%attr, $class;

    # register our tree handler when asked to do so
    $self->register($args{Name}, $args{AutoHandle}, \&tree_handler)
        if $args{AutoHandle};

    # find the sockets used to communicate with AgentX master..
    my ($block, $to_sec, $to_usec, @fd_set) = SNMP::_get_select_info();
    for my $fd (@fd_set) {
        push @watchers, AnyEvent->io(
            fh => $fd,  poll => "r",  cb => sub { agent_check($self) },
        );
    }

    # regularly check the AgentX socket
    push @watchers, AnyEvent->timer(
        after       => 0,
        interval    => $args{Ping},
        cb          => sub { agent_check($self) },
    );

    # set up the timers for the OID tree update handlers
    my $update_handlers = $args{AutoUpdate};
    for my $def (@$update_handlers) {
        my ($callback, $delay) = @$def;
        push @watchers, AnyEvent->timer(
            after       => 0,
            interval    => $delay,
            cb          => sub { $callback->($self) },
        );
    }

    return $self
}


#
# register()
# --------
sub register {
    my ($self, $name, $oid, $callback) = @_;
print STDERR "- register ($name, $oid, $callback)\n";

    $self->{agent}->register($name, $oid, sub { $callback->($self, [@_]) })
        or croak "error: can't register callback\n";

    return $self
}


#
# agent_check()
# -----------
sub agent_check {
    my ($self) = @_;
print STDERR "- agent_check\n";

    # process the incoming data and invoke the callback
    SNMP::_check_timeout();
    $self->{agent}->agent_check_and_process(0);

    return $self
}


#
# run()
# ---
sub run {
    AnyEvent->condvar->recv
}


#
# tree_handler()
# ------------
sub tree_handler {
    my ($self, $args) = @_;
    my ($handler, $reg_info, $request_info, $requests) = @$args;
print STDERR "- tree_handler\n";
    my $oid_tree = $self->{oid_tree};
    my $oid_list = $self->{oid_list};

    # the rest of the code works like a classic NetSNMP::agent callback
    my $mode = $request_info->getMode;

    for (my $request = $requests; $request; $request = $request->next) {
        my $oid = $request->getOID->as_oid;

        if ($mode == MODE_GET) {
            if (exists $oid_tree->{$oid}) {
                $request->setValue(
                    $oid_tree->{$oid}[TYPE],
                    $oid_tree->{$oid}[VALUE]
                );
            }
            else {
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
                next
            }
        }
        elsif ($mode == MODE_GETNEXT) {
            my $next_oid = find_next_oid($oid_list, $oid);

            if (exists $oid_tree->{$next_oid}) {
                # /!\ no intermediate vars. see comment at end
                $request->setOID($next_oid);
                $request->setValue(
                    $oid_tree->{$next_oid}[TYPE],
                    $oid_tree->{$next_oid}[VALUE]
                );
            }
            else {
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
                next
            }
        }
        else {
            $request->setError($request_info, SNMP_ERR_GENERR);
            next
        }
    }
}


#
# ev_add_oid_entry()
# ----------------
sub add_oid_entry {
    my ($self, $oid, $type, $value) = @_;
print STDERR "- add_oid_entry($oid, $type, $value)\n";

    my $oid_tree = $self->{oid_tree};

    # make sure that the OID start with a dot
    $oid = ".$oid" unless index($oid, ".") == 0;

    # add the given entry to the tree
    $oid_tree->{$oid} = [ $type, $value ];

    # calculate the sorted list of OID entries
    @{ $self->{oid_list} } = HAVE_SORT_KEY_OID ?
        oidsort(keys %$oid_tree) : sort by_oid keys %$oid_tree;

    return $self
}


#
# ev_add_oid_tree()
# ---------------
sub add_oid_tree {
    my ($self, $new_tree) = @_;
print STDERR "- add_oid_tree\n";

    my $oid_tree = $self->{oid_tree};

    # make sure that the OIDs start with a dot
    my @oids = map { index($_, ".") == 0 ? $_ : ".$_" } keys %$new_tree;

    # add the given entries to the tree
    @{$oid_tree}{@oids} = values %$new_tree;

    # calculate the sorted list of OID entries
    @{ $self->{oid_list} } = HAVE_SORT_KEY_OID ?
        oidsort(keys %$oid_tree) : sort by_oid keys %$oid_tree;

    return $self
}



# ==============================================================================
# Hackery
#

{
    package ### live-patch NetSNMP::OID
            NetSNMP::OID;
    sub as_oid { return join ".", "", $_[0]->to_array }
}


__PACKAGE__

__END__

