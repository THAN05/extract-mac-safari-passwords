# True Key JSON/CSV export converter
#
# Copyright 2016 Mike Cappella (mike@cappella.us)

package Converters::Truekey;

our @ISA 	= qw(Exporter);
our @EXPORT     = qw(do_init do_import do_export);
our @EXPORT_OK  = qw();

use v5.14;
use utf8;
use strict;
use warnings;
#use diagnostics;

binmode STDOUT, ":utf8";
binmode STDERR, ":utf8";

use Utils::PIF;
use Utils::Utils;
use Utils::Normalize;

use Time::Local qw(timelocal);
use Time::Piece;
# Force lib included CSV_PP for consistency
BEGIN { $ENV{PERL_TEXT_CSV}='Text::CSV_PP'; }
use Text::CSV qw/csv/;	# newer versions export to CSV
use JSON::PP;		# early versions exported as JSON

=pod

=encoding utf8

=head1 True Key converter module

=head2 Platforms

=over

=item B<macOS>: Initially tested with version 1.12.0

=item B<Windows>: Untested

=back

=head2 Description

Converts your exported True Key data to 1PIF for 1Password import.

=head2 Instructions

Launch True Key.

Export its login items as a text file using the settings gear icon in the upper right corner of the user interface.
Select C<App Settings> below that, and click the C<Export> button in the C<Export Data> section of the settings at the bottom of the list.
Click C<Continue> when the export warning dialog is presented, enter your master password when prompted, and click the C<Unlock> button.
When the C<Save> dialog appears, navigate to your B<Desktop> folder, and in the C<Save As> area, enter the file name B<pm_export>.
Click the C<Save> button.
After exporting the data, your file will be named B<pm_export.csv> or B<pm_export.json>, depending on your version of True Key.

You may now quit True Key.

=head2 Notes

This converter supports cross-platform conversion (the export may be exported on one platform, but converted on another).

=cut

# fields to be ignored from the CSV output
my @ignored_fields = (
    'autologin',
    'hexColor',
    'kind',
    'protectedWithPassword',
    'subdomainOnly',
    'tk_export_version',
);

my %card_field_specs = (
    login =>                    { textname => undef, fields => [
        [ 'url',		1, qr/^url$/, ],
        [ 'username',		1, qr/^login$/, ],
        [ 'password',		1, qr/^password$/, ],
    ]},
    driverslicense =>           { textname => undef, fields => [
        [ 'number',		1, qr/^number$/, ],
        #[ 'birthdate',		1, qr/^dateOfBirth$/,		{ func => sub { return date2epoch($_[0]) } }],
        #[ 'expiry_date',	1, qr/^expirationDate$/,	{ func => sub { return date2monthYear($_[0]) } }],
        [ 'firstname',		1, qr/^firstName$/, ],		# see 'Fixup: combine names'
        [ 'lastname',		1, qr/^lastName$/, ],		# see 'Fixup: combine names'
        [ 'fullname',		1, qr/^First__Last$/, ],	# see 'Fixup: combine names' - input never matches
        [ 'sex',		1, qr/^gender$/, 		{ func => sub { return $_[0] eq '0' ? 'male' : 'female' } }],
        [ 'state',		1, qr/^state$/, ],
    ]},
    identity =>           	{ textname => undef, fields => [
        [ 'firstname',		1, qr/^firstName$/, ],
        [ 'lastname',		1, qr/^lastName$/, ],
        [ 'sex',		1, qr/^gender$/, 		{ func => sub { return $_[0] eq '0' ? 'male' : 'female' } }],
        [ 'company',		1, qr/^company$/, ],
        [ 'defphone',		1, qr/^telephone$/, ],
        [ 'email',		1, qr/^email$/, ],
        [ 'website',		1, qr/^website$/, ],
        [ 'address',		1, qr/^__Address$/, ],		# see Fixup: address
        #[ 'birthdate',		1, qr/^dateOfBirth$/, 		{ func => sub { return date2epoch($_[0]) } } ],
    ]},
    membership =>           	{ textname => undef, fields => [
        [ 'member_name',	1, qr/^memberId$/, ],
        [ 'pin',		1, qr/^password$/, ],
        [ 'phone',		1, qr/^phoneNumber$/, ],
        [ 'firstname',		1, qr/^firstName$/, ],		# see 'Fixup: combine names'
        [ 'lastname',		1, qr/^lastName$/, ],		# see 'Fixup: combine names'
        [ 'member_name',	1, qr/^First__Last$/, ],	# see 'Fixup: combine names' - input never matches
        #[ 'member_since',	1, qr/^memberSince$/,		{ func => sub { return date2monthYear($_[0]) } }],
        #[ 'expiry_date',	1, qr/^expiryDate$/,		{ func => sub { return date2monthYear($_[0]) } }],
    ]},
    passport =>           	{ textname => undef, fields => [
        [ 'country',		1, qr/^title$/, ],
        [ 'issuing_country',	1, qr/^deliveryPlace$/, ],
        [ 'number',		1, qr/^number$/, ],
        [ 'sex',		1, qr/^gender$/, 		{ func => sub { return $_[0] eq '0' ? 'male' : 'female' } }],
        [ 'birthplace',		1, qr/^country$/, ],
        [ 'firstname',		1, qr/^firstName$/, ],		# see 'Fixup: combine names'
        [ 'lastname',		1, qr/^lastName$/, ],		# see 'Fixup: combine names'
        [ 'fullname',		1, qr/^First__Last$/, ],	# see 'Fixup: combine names' - input never matches
        #[ 'expiry_date',	1, qr/^expirationDate$/,	{ func => sub { return date2epoch($_[0]) } }],
    ]},
    socialsecurity =>          	{ textname => undef, fields => [
        [ 'number',		1, qr/^number$/, ],
        [ 'firstname',		1, qr/^firstName$/, ],		# see 'Fixup: combine names'
        [ 'lastname',		1, qr/^lastName$/, ],		# see 'Fixup: combine names'
        [ 'name',		1, qr/^First__Last$/, ],	# see 'Fixup: combine names' - input never matches
    ]},
    creditcard =>          	{ textname => undef, fields => [
        [ 'cardholder',		1, qr/^cardholder$/, ],
        [ 'type',		1, qr/^type$/, 			{ func => sub { return getCCname($_[0]) } }],
        [ 'ccnum',		1, qr/^number$/, ],
        #[ 'validFrom',		1, qr/^issuedDate$/,		{ func => sub { return date2monthYear($_[0]) } }],
        #[ 'expiry',		1, qr/^expiryDate$/,		{ func => sub { return date2monthYear($_[0]) } }],
    ]},
);

sub getCCname {
    my $index = shift;

    my @cctypes = qw/visa mastercard amex other/;
    bail "Unexpected credit card ID: $index.  Please report"	if $index >= @cctypes;
    return $cctypes[$index];
}


$DB::single = 1;					# triggers breakpoint when debugging

sub do_init {
    return {
	'specs'		=> \%card_field_specs,
	'imptypes'  	=> undef,
        'opts'          => [],
    };
}

sub do_import {
    my ($file, $imptypes) = @_;
    my %Cards;

    my $data = slurp_file($file);

    my $n;
    if ($data =~ /^{".*}$/) {
	$n = process_json(\$data, \%Cards, $imptypes);
    }
    else {
	$n = process_csv($file, \%Cards, $imptypes);
    }
	
    summarize_import('item', $n - 1);
    return \%Cards;
}

sub process_csv {
    my ($file, $Cards, $imptypes) = @_;

    my $parsed;
    my @column_names;
    eval { $parsed = csv(
	    in => $file,
	    auto_diag => 1,
	    diag_verbose => 1,
	    detect_bom => 1,
	    sep_char => ",",
	    munge_column_names => sub { $_ },		# dont lc headers
	    keep_headers => \@column_names,
	);
    };
    $parsed or
	bail "Failed to parse file: $file";

    my ($n, $rownum) = (1, 1);
    while (my $row = shift @$parsed) {
	debug 'ROW: ', $rownum++;

	my (%cmeta, @fieldlist, $tmp);
	my ($title_key, $note_key);

	my $itype = $row->{'kind'};

	$itype = 'driverslicense'	if $itype eq 'drivers';
	$itype = 'creditcard'		if $itype eq 'cc';
	$itype = 'socialsecurity'	if $itype eq 'ssn';

	if ($itype eq 'login') {
	    ($title_key, $note_key) = ('name', 'memo');
	}
	elsif ($itype eq 'note') {
	    ($title_key, $note_key) = ('title', 'document_content');
	}
	elsif ($itype =~ /^driverslicense|identity|creditcard|membership|passport|socialsecurity$/) {
	    ($title_key, $note_key) = ('title', 'note');
	}
	else {
	    bail "Currently unknown TrueKey type: '$itype' - please report";
	}

	$cmeta{'title'} = $row->{$title_key} || 'Untitled';
	$cmeta{'notes'} = $row->{$note_key}	if exists $row->{$note_key} and $row->{$note_key} ne '';

	if ($row->{'favorite'} eq 'true') {
	    $cmeta{'tags'}	= 'Favorite';
	    $cmeta{'folder'}	= [ 'Favorite' ];
	}
	for (qw/kind name memo title document_content note favorite/) {
	    delete $row->{$_};
	}

	# Fixup: Address
	if ($itype eq 'identity') {
	    my %h;
	    $h{'street'} = myjoin(' ', $row->{'streetNumber'} // '', $row->{'street'} // '');
	    $h{'city'} = $row->{'city'}		if $row->{'city'};
	    $h{'state'} = $row->{'state'}	if $row->{'state'};
	    $h{'zip'} = $row->{'zipCode'}	if $row->{'zipCode'};
	    $row->{'__Address'} = \%h		if keys %h;
	    delete $row->{$_}	for qw/street streetNumber city state zipCode/;
	}

	for my $label (keys %$row) {
	    next if ($row->{$label} eq '' or grep { $label eq $_ } @ignored_fields);
	    my $value = $row->{$label};
	    next if not defined $value or $value eq '';
	    push @fieldlist, [ $label => $value ];		# @fieldlist maintains card's field order
	}

	# Fixup: combine names
	if ($itype =~ /^driverslicense|membership|passport|socialsecurity$/) {
	    my ($first, $last, @found);
	    $first = $found[0][1]	if @found = grep { $_->[0] eq 'firstName' } @fieldlist;
	    $last  = $found[0][1]	if @found = grep { $_->[0] eq 'lastName' } @fieldlist;

            if ($first or $last) {
                push @fieldlist, [ 'First__Last' =>  myjoin(' ',  $first, $last) ];
                debug "\t\tfield added: $fieldlist[-1][0] -> $fieldlist[-1][1]";
            }
        }

	if (do_common($Cards, \@fieldlist, \%cmeta, $imptypes, $itype)) {
	    $n++;
	}
    }
    return $n;
}

sub process_json {
    my ($data, $Cards, $imptypes) = @_;

    my $decoded = decode_json $$data;

    exists $decoded->{'logins'} or
	bail "Export JSON file - unexpected format";

    my $n = 1;
    for my $entry (@{$decoded->{'logins'}}) {
	my (%cmeta, @fieldlist);

	$cmeta{'title'} = $entry->{'name'};
	$cmeta{'notes'} = $entry->{'memo'};
	if ($entry->{'favorite'} eq 'true') {
	    $cmeta{'tags'} = 'Favorite';
	    $cmeta{'folder'}  = [ 'Favorite' ];
	}

	for my $label (qw/login password url/) {
	    my $value = $entry->{$label};
	    next if not defined $value or $value eq '';
	    push @fieldlist, [ $label => $value ];		# @fieldlist maintains card's field order
	}

	if (do_common($Cards, \@fieldlist, \%cmeta, $imptypes, undef)) {
	    $n++;
	}
    }

    return $n;
}

sub do_common {
    my ($Cards, $fieldlist, $cmeta, $imptypes, $itype) = @_;

    $itype = find_card_type($fieldlist, $itype);

    # skip all types not specifically included in a supplied import types list
    return undef	if defined $imptypes and (! exists $imptypes->{$itype});

    my $normalized = normalize_card_data(\%card_field_specs, $itype, $fieldlist, $cmeta);
    my $cardlist   = explode_normalized($itype, $normalized);

    for (keys %$cardlist) {
	print_record($cardlist->{$_});
	push @{$Cards->{$_}}, $cardlist->{$_};
    }

    return 1;
}

sub do_export {
    add_custom_fields(\%card_field_specs);
    create_pif_file(@_);
}

sub find_card_type {
    my ($fieldlist, $itype) = @_;

    # CSV export data contains the entry type
    if ($itype) {
	debug "type defined as '$itype'";
	return $itype;
    }

    for my $type (sort by_test_order keys %card_field_specs) {
	for my $cfs (@{$card_field_specs{$type}{'fields'}}) {
	    for (@$fieldlist) {
		if ($cfs->[CFS_TYPEHINT] and $_->[0] =~ $cfs->[CFS_MATCHSTR]) {
		    debug "type detected as '$type' (key='$_->[0]')";
		    return $type;
		}
	    }
	}
    }

    debug "\t\ttype defaulting to 'note'";
    return 'note';
}

# sort logins as the last to check
sub by_test_order {
    return  1 if $a eq 'login';
    return -1 if $b eq 'login';
    $a cmp $b;
}

# Date converters
#     yyyy-mm-ddThh:mm:ss-Zh:Zm
#     1485-03-02T00:00:00-08:00	- can export garbage dates
sub parse_date_string {
    local $_ = $_[0];
    my $when = $_[1] || 0;					# -1 = past only, 0 = assume this century, 1 = future only, 2 = 50-yr moving window

    if (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}-\d{2}:\d{2}$/) {
	# remove the : separator between the TZ components
	s/(-\d{2}):(\d{2})$/$1$2/;
	my $t = eval { Time::Piece->strptime($_, "%Y-%m-%dT%H:%M:%S%z") };
	if ($t and $t->year > 1900 and $t->year < 2100) {
	    return $t;
	}
    }

    return undef;
}

sub date2epoch {
    my $t = parse_date_string @_;
    return undef if not defined $t;
    return defined $t->year ? 0 + timelocal($t->sec, $t->minute, $t->hour, $t->mday, $t->mon - 1, $t->year): $_[0];
}

sub date2monthYear {
    my $t = parse_date_string @_;
    return undef if not defined $t;
    return defined $t->year ? $t->strftime("%Y%m") : $_[0];
}


1;
