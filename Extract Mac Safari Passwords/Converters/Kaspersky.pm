# Kaspersky Password Manager text export converter
#
# Copyright 2021 Mike Cappella (mike@cappella.us)

package Converters::Kaspersky;

our @ISA 	= qw(Exporter);
our @EXPORT     = qw(do_init do_import do_export);
our @EXPORT_OK  = qw();

use v5.16;
use utf8;
use strict;
use warnings;
#use diagnostics;

binmode STDOUT, ":utf8";
binmode STDERR, ":utf8";

use Utils::PIF;
use Utils::Utils;
use Utils::Normalize;


=pod

=encoding utf8

=head1 Kaspersky Password Manager converter module

=head2 Platforms

=over

=item B<macOS>: N/A - vault export unavailable

=item B<Windows>: Initially tested using 9.0.2.15298

=back

=head2 Description

Converts your exported Kaspersky data to 1PIF for 1Password import.

=head2 Instructions

Launch Kaspersky Password Manager.

Export its database to a text file by clicking on the C<< ... Additional >> item at the bottom left of the application.
From there, select the C<< Settings >> item, and then click C<< Import/Export >>.
Scroll the right-side list to get to the B<Export to text file> area.
Click the C<Export> button.
When the C<< Specify file location >> dialog appears, within it, navigate to your Desktop, and 
save the file with the name B<pm_export.txt> to your Desktop.

You may now quit Kaspersky Password Manager.

=head2 Notes

The Kaspersky Password Manager's text export is quite limited.
You should retain Kaspersky Password Manager until you've confirmed you have all the data you require.

Kaspersky Password Manager only exports the categories B<Applications>, B<Websites>, B<Notes>; no other categories are exported.
The B<Applications> category is treated similarly to B<Websites>, both will be stored as 1Password B<Login> records.

Many record properties are not exported; only the basic fields are available.

The format of the Kaspersky text export file is marginally structured, but is ambiguous.
The converter uses this expected structure to determine the category and record boundaries.
However, if your records contain these patterns (in the Comments or Text fields),
the converter may mis-detect records.

=cut

my %card_field_specs = (
    #
    # DO NOT REORDER the array order of the items below.  Their order here must match
    # the order the field labels are exported in the Kaspersky export file.
    #
    application =>              { textname => 'Applications', type_out => 'login', fields => [
	[ '_title',		0, 'Application' ],
	[ '_subtitle',		0, 'Login name', 			{ to_title => 'value' } ],
	[ 'username',		0, 'Login' ],
	[ 'password',		0, 'Password' ],
	[ '_note',		0, 'Comment' ],
    ]},
    note =>                  	{ textname => 'Notes', fields => [
	[ '_title',		0, 'Name' ],
	[ '_note',		0, 'Text' ],
    ]},
    website =>                  { textname => 'Websites', type_out => 'login', fields => [
	[ '_title',		0, 'Website name' ],
	[ 'url',		0, 'Website URL' ],
	[ '_subtitle',		0, 'Login name', 			{ to_title => 'value' } ],
	[ 'username',		0, 'Login' ],
	[ 'password',		0, 'Password' ],
	[ '_note',		0, 'Comment' ],
    ]},
);

my %fieldname_to_capturename;
my %capturename_to_fieldname;

$DB::single = 1;					# triggers breakpoint when debugging

sub do_init {
    return {
	'specs'		=> \%card_field_specs,
	'imptypes'  	=> undef,
	'opts'		=> [],
    };
}

sub make_template_re {
    my $textname = shift;

    my $eol = $^O eq 'MSWin32' ? "\x0a" : "\x0d\x0a";
    my @found = grep { $card_field_specs{$_}->{'textname'} eq $textname } keys %card_field_specs;
    @found or
	bail "Unable to find a definition for section '$textname' in %card_field_specs";
    @found == 1 or 
	bail "Too many matches for section '$textname' in %card_field_specs";

    my $parts;
    for (@{$card_field_specs{$found[0]}->{'fields'}}) {
	my $newstr;
	($newstr = $_->[CFS_MATCHSTR]) =~ s/\s/_/;
	$fieldname_to_capturename{$_->[CFS_MATCHSTR]}	= $newstr;
	$capturename_to_fieldname{$newstr}		= $_->[CFS_MATCHSTR];
	$parts .= "$_->[CFS_MATCHSTR]: (?<$newstr>.*?)$eol";
    }
    return $parts;
}

sub do_import {
    my ($file, $imptypes) = @_;
    my %Cards;

    my $data = slurp_file($file, 'utf8');
    $data =~ s/\A\N{BOM}//;					# remove BOM

    my $n = 1;
    while ($data =~ /\S/ms) {

	if ($data =~ s/\A(Websites|Applications|Notes)\R\R//ms) {
	    my $template_re = make_template_re($1);

	    # XXX fixme - handle the many hard-coded special-cases below.

	    #my $itype = find_card_type($cardstr);
	    my $itype = lc $1;
	    $itype =~ s/s$//;		# de-pluralize

	    while ($data =~ s/${template_re}\R---\R\R//ms) {
		my %captured;
		$captured{$capturename_to_fieldname{$_}} = $+{$_}	 for keys %+;

		my (%cmeta, @fieldlist);

		# skip all types not specifically included in a supplied import types list
		next if defined $imptypes and (! exists $imptypes->{$itype});

		if ($itype =~ /^website|application$/) {
		    if ($itype eq 'website') {
			$cmeta{'title'} = $captured{'Website name'};
			delete $captured{'Website name'};
		    }
		    else {
			$cmeta{'title'} = $captured{'Application'};
			delete $captured{'Application'};
		    }

		    $cmeta{'notes'} = $captured{'Comment'}		if $captured{'Comment'} ne '';
		    delete $captured{'Comment'};

		    for (keys %captured) {
			push @fieldlist, [ $_, $captured{$_} ];
		    }
		}
		elsif ($itype eq 'note') {
		    $cmeta{'title'} = $captured{'Name'};
		    delete $captured{'Name'};

		    $cmeta{'notes'} = $captured{'Text'}			if $captured{'Text'} ne '';
		    delete $captured{'Text'};

		}
		else {
		    bail "Unexpected type - please report";
		}

		$cmeta{'notes'} =~ s/\x0d\x0d\x0a/\n/g			if exists $cmeta{'notes'};


		my $normalized = normalize_card_data(\%card_field_specs, $itype, \@fieldlist, \%cmeta);
		my $cardlist   = explode_normalized($itype, $normalized);

		for (keys %$cardlist) {
		    print_record($cardlist->{$_});
		    push @{$Cards{$_}}, $cardlist->{$_};
		}
		$n++;
	    }
	}
	else {
	    bail "Unexpected file format";
	}

	$data =~ s/\A\s+//;
    }

    summarize_import('item', $n - 1);
    return \%Cards;
}

sub do_export {
    add_custom_fields(\%card_field_specs);
    create_pif_file(@_);
}

sub find_card_type {
    my $c = shift;
    my $type;

    for $type (keys %card_field_specs) {
	for my $cfs (@{$card_field_specs{$type}{'fields'}}) {
	    if (defined $cfs->[CFS_MATCHSTR] and $c =~ /$cfs->[CFS_MATCHSTR]/ms) {
		if ($cfs->[CFS_TYPEHINT]) {
		    debug "\t\ttype detected as '$type'";
		    return $type;
		}
	    }
	}
    }

    if ($c =~ /^User Name:?/ms and $c =~ /^Password /ms) {
	$type = ($c =~ /^System:? /ms or $c =~ /^PIN /ms or $c =~ /^Account Type /ms) ? 'password' : 'login';
    }
    else {
	$type = 'note';
    }

    debug "\t\ttype defaulting to '$type'";
    return $type;
}

1;
