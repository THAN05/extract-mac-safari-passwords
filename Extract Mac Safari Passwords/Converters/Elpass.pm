# Elpass JSON export converter
#
# Copyright 2020 Mike Cappella (mike@cappella.us)

package Converters::Elpass;

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

use Encode;
use JSON::PP;
use Time::Piece;

=pod

=encoding utf8

=head1 Elpass converter module

=head2 Platforms

=over

=item B<macOS>:  Initially tested with version 1.1.9 (277)

=item B<Windows>: N/A

=back

=head2 Description

Converts your exported Elpass JSON data to 1PIF for 1Password import.

=head2 Instructions

Launch the desktop version of Elpass.
You will export your Elpass data as unencrypted B<JSON> data.

Under the C<File E<gt> Export> menu, select the C<Export All items to .elpassexport File...> menu item.
Enter your master password when requested.
When the C<Elpass> export dialog appears, navigate to your Desktop folder,
and save the file with the name B<pm_export> to your Desktop.

You should now have the file named B<pm_export.elpassexport> on your Desktop - use this file name on the command line.

You may now quit Elpass.

=head2 Notes

Elpass' Identification category is a free-form entry type, and therefore must be imported as a Secure Note.

Elpass' Bank Card category has several sub-categories: Credit Card, Debit Card, Prepaid Card.
These will be exported as Credit Card entries.
The sub-category of Bank Account conains field names that are nonsensical for such a category.
These will be placed in the Notes section of the entry.

=cut

# The following top-level field names will be ignored.
#
my @ignoredFields = qw(
    securityLevel
    uuid
    disableAutoFill
    disableAutoFillOTP
    disableAutoSubmit
);

my %card_field_specs = (
    bankacct =>			{ textname => 'Bank Account', fields => [
	[ '_cvv',		0, qr/^cardVerificationCode$/, ],
	[ 'telephonePin',	0, qr/^pin$/, ],
	[ 'bankName',		0, qr/^issuingBank$/, ],
	[ 'owner',		0, qr/^cardholderName$/, ],
	[ 'accountNo',		0, qr/^cardNumber$/, ],
    ]},

    creditcard =>		{ textname => 'Credit Card', fields => [
	[ 'cardholder',		0, qr/^cardholderName$/, ],
	[ 'type',		0, qr/^cardBrand$/, ],
	[ 'ccnum',		0, qr/^cardNumber$/, ],
	[ 'cvv',		0, qr/^cardVerificationCode$/, ],
	[ 'pin',		0, qr/^pin$/, ],
	[ 'bank',		0, qr/^issuingBank$/, ],
	[ '_expiryMonth',	0, qr/^cardExpiryDateMonth$/, ],	# see 'Fixup: bankcard dates'
	[ '_expiryYear',	0, qr/^cardExpiryDateYear$/, ],		# see 'Fixup: bankcard dates'
	[ 'expiry',		0, qr/^_expiresMonthYear$/, ],		# see 'Fixup: bankcard dates'
    ]},
    debitcard =>		{ textname => 'Debit Card', type_out => 'creditcard', fields => [
	[ 'cardholder',		0, qr/^cardholderName$/, ],
	[ 'type',		0, qr/^cardBrand$/, ],
	[ 'ccnum',		0, qr/^cardNumber$/, ],
	[ 'cvv',		0, qr/^cardVerificationCode$/, ],
	[ 'pin',		0, qr/^pin$/, ],
	[ 'bank',		0, qr/^issuingBank$/, ],
	[ '_expiryMonth',	0, qr/^cardExpiryDateMonth$/, ],	# see 'Fixup: bankcard dates'
	[ '_expiryYear',	0, qr/^cardExpiryDateYear$/, ],		# see 'Fixup: bankcard dates'
	[ 'expiry',		0, qr/^_expiresMonthYear$/, ],		# see 'Fixup: bankcard dates'
    ]},
    prepaidcard =>		{ textname => 'Prepaid Card', type_out => 'creditcard', fields => [
	[ 'cardholder',		0, qr/^cardholderName$/, ],
	[ 'type',		0, qr/^cardBrand$/, ],
	[ 'ccnum',		0, qr/^cardNumber$/, ],
	[ 'cvv',		0, qr/^cardVerificationCode$/, ],
	[ 'pin',		0, qr/^pin$/, ],
	[ 'bank',		0, qr/^issuingBank$/, ],
	[ '_expiryMonth',	0, qr/^cardExpiryDateMonth$/, ],	# see 'Fixup: bankcard dates'
	[ '_expiryYear',	0, qr/^cardExpiryDateYear$/, ],		# see 'Fixup: bankcard dates'
	[ 'expiry',		0, qr/^_expiresMonthYear$/, ],		# see 'Fixup: bankcard dates'
    ]},

    login =>			{ textname => 'login', fields => [
	[ 'username',		0, qr/^username$/, ],
	[ 'password',		0, qr/^password$/, ],
	[ 'url',		0, qr/^url$/, ],			# see 'Fixup: main + additional URLs for logins'
	[ '*additionalurls',	0, qr/^additionalurls$/, ],		# see 'Fixup: main + additional URLs for logins'
	[ '_totp',		0, qr/^otpURL$/, ],
    ]},

    password =>			{ textname => 'password', fields => [
	[ 'password',		0, qr/^password$/, ],
    ]},

    note =>			{ textname => 'securenote', fields => [
    ]},
);

$DB::single = 1;					# triggers breakpoint when debugging

sub do_init {
    return {
	'specs'		=> \%card_field_specs,
	'imptypes'  	=> undef,
        'opts'          => [ ],
    }
}

sub do_import {
    my ($file, $imptypes) = @_;
    my %Cards;

    my $data = slurp_file($file, 'utf8');

    my $n;
    if ($data =~ /^\[/ and $data =~ /\]$/) {
	$n = process_json(\$data, \%Cards, $imptypes);
    }

    summarize_import('item', $n - 1);
    return \%Cards;
}

sub process_json {
    my ($data, $Cards, $imptypes) = @_;

    my $decoded = decode_json Encode::encode('UTF-8', $$data);

    unless ($decoded and scalar @$decoded) {
	bail "Unable to find any items in the Elpass JSON export file";
    }

    my $n = 1;

    for my $entry (@$decoded) {
	my (%cmeta, @fieldlist);

	my $itype;
	# For bankcard, cardType is a subtype
	if ($entry->{'_type'} eq 'bankcard') {
	    $itype = find_card_type($entry->{'cardType'});
	    delete $entry->{'cardType'};
	}
	else {
	    $itype = find_card_type($entry->{'_type'});
	}
	delete $entry->{'_type'};
	debug "Processing type: ", $itype;

	$cmeta{'title'} = $entry->{'title'} // 'Untitled';
	delete $entry->{'title'};

	@{$cmeta{'tags'}} = @{$entry->{'tags'}}		if exists $entry->{'tags'} and @{$entry->{'tags'}};
	delete $entry->{'tags'};

	push @{$cmeta{'tags'}}, 'Favorite'		if $entry->{'favIdx'} ne '0';
	delete $entry->{'favIdx'};

	if (exists $entry->{'notes'}) {
	    push @{$cmeta{'notes'}}, $entry->{'notes'};
	}
	delete $entry->{'notes'};


	$cmeta{'created'}  = $entry->{'createdAt'}		if exists $entry->{'createdAt'};
	$cmeta{'modified'} = $entry->{'updatedAt'}		if exists $entry->{'updatedAt'};
	delete $entry->{'createdAt'};
	delete $entry->{'updatedAt'};

	# otherFields section
	#
	for my $field (keys %{$entry->{'otherFields'}}) {
	    #next if grep { $field eq $_ } @ignoredIdentifiers;

	    if ($entry->{'otherFields'}{$field} ne '') {
		push @fieldlist, [ $field => $entry->{'otherFields'}{$field} ]		
	    }
	}
	delete $entry->{'otherFields'};

	# customFields section
	#
	for (@{$entry->{'customFields'}}) {
	    next if $_->{'value'} eq '';

	    my $title = $_->{'title'} eq '' ? 'unnamed' : $_->{'title'};
	    push @fieldlist, [ 'custom field::' . $title => $_->{'value'} ]		
	}
	delete $entry->{'customFields'};

	if (exists $entry->{'attachments'}) {
	    push @{$cmeta{'notes'}}, 'original attachment(s): ' . join('; ', map { $_->{'fileName'} } @{$entry->{'attachments'}});
	    delete $entry->{'attachments'};
	}

	# Fixup: main + additional URLs for logins
	if ($itype eq 'login' and exists $entry->{'domains'}) {
	    $entry->{'url'} = shift @{$entry->{'domains'}};
	    $entry->{'additionalurls'} = join("\n", @{$entry->{'domains'}})		if @{$entry->{'domains'}};
	    delete $entry->{'domains'};
        }

	# Fixup: bankcard dates
	elsif ($itype =~ /^(credit|debit|prepaid)card$/) {
	    if (exists $entry->{'cardExpiryDateMonth'} and exists $entry->{'cardExpiryDateYear'}) {
		if (my $monthYear = date2monthYear(join '-', $entry->{'cardExpiryDateYear'}, $entry->{'cardExpiryDateMonth'})) {
		    $entry->{"_expiresMonthYear"} = $monthYear;
		    delete $entry->{'cardExpiryDateMonth'};
		    delete $entry->{'cardExpiryDateYear'};
		}
	    }
	}

	for my $field (keys %$entry) {
	    push @fieldlist, [ $field => $entry->{$field} ]	unless grep { $field eq $_ } @ignoredFields;
	    delete $entry->{$field};
	}

	if (do_common($Cards, \@fieldlist, \%cmeta, $imptypes, $itype)) {
	    $n++;
	}
    }

    return $n;
}

sub do_common {
    my ($Cards, $fieldlist, $cmeta, $imptypes, $itype) = @_;

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
    my $type = shift;

    for my $key (keys %card_field_specs) {
	return $key	if $card_field_specs{$key}{'textname'} eq $type;
    }

    return 'note';
}

# Date converters
sub parse_date_string {
    local $_ = $_[0];

    my $t = eval { Time::Piece->strptime($_, "%Y-%m") };
    if ($t) {
	return $t;
    }

    return undef;
}

sub date2monthYear {
    my $t = parse_date_string(@_);
    return defined $t && defined $t->year ? sprintf("%d%02d", $t->year, $t->mon) : '';
}

1;
