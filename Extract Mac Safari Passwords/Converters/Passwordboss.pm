# Password Boss JSON export converter
#
# Copyright 2020 Mike Cappella (mike@cappella.us)

package Converters::Passwordboss;

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

=head1 Password Boss converter module

=head2 Platforms

=over

=item B<macOS>:  Initially tested with version 5.5.577 db49 rel: 44

=item B<Windows>: Initially tested with version 5.5.4747.0

=back

=head2 Description

Converts your exported Password Boss JSON data to 1PIF for 1Password import.

=head2 Instructions

Launch the desktop version of Password Boss.
You will export your Password Boss data as unencrypted B<JSON> data.

Under the C<File E<gt> Export data> menu, select the C<Password Boss JSON - not encrypted ...> menu item.
When the C<Password Boss> export dialog appears, navigate to your Desktop folder,
and save the file with the name B<pm_export.json> to your Desktop.
Click C<OK> when the confirmation dialog appears.

You may now quit Password Boss.

=head2 Options

The C<< --appendsubtitle >> option will append any subtitle value onto the end of the item's title.
This can make similarly named titles less ambiguous.  The subtitle value is set by Password Boss on export,
and will typically contain a record's most disambiguating field.
Without this option, the subtitle field will go to the notes area.

=head2 Notes

Password Boss employs several Personal Identity categories (Address, Company, Email, Name, Phone),
whereas 1Password stores this information in a single Identity record.
The Password Boss export contains no information linking these records together, so the converter
must treat them as independent items.  The converter will create an Identify record for each
Personal Identity > Name record found.
But the other Personal Identity types will be placed in Secure Notes, where you may copy / paste the
values stored in the Notes section to the relevant fields in the corresponding Identity record.

=cut

# The following top-level field names will be ignored.
#
my @ignoredFields = qw(
    color
);

# The following field names will be ignored in an item's "identifiers" section.
#
my @ignoredIdentifiers = qw(
    ignoreItemInSecurityScore
    password_age
    password_visible_recipient
    remote_connection
    windows_application
);

my %card_field_specs = (
    alarmcode =>		{ textname => 'SN::AlarmCode', type_out => 'note', fields => [
	[ '_alarm_company',	0, qr/^alarm_company$/,  { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'alarm company' ] } ],
	[ '_phonenumber',	0, qr/^phoneNumber$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'phone number' ] } ],
	[ '_password',		0, qr/^password$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_concealed, 'password' ] } ],
	[ '_alarm_code',	0, qr/^alarm_code$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_concealed, 'alarm_code' ] } ],
    ]},

    app =>			{ textname => 'PV::Application', type_out => 'login', fields => [
	[ 'username',		0, qr/^username$/, ],
	[ 'password',		0, qr/^password$/, ],
	[ '_type',		0, qr/^type$/, ],
	[ '_application',	0, qr/^application$/, ],
    ]},

    bankaccount =>		{ textname => 'DW::Bank', type_out => 'bankacct', fields => [
	[ 'bankName',		0, qr/^bank_name$/, ],
	[ 'owner',		0, qr/^nameOnAccount$/, ],
	[ 'accountNo',		0, qr/^accountNumber$/, ],
	[ 'routingNo',		0, qr/^routingNumber$/, ],
	[ 'swift',		0, qr/^swift$/, ],
	[ 'iban',		0, qr/iban$/, ],
	[ 'branchPhone',	0, qr/^bank_phone$/, ],
	[ 'telephonePin',	0, qr/^pin$/, ],
    ]},

    creditcard =>		{ textname => 'DW::CreditCard', fields => [
	[ 'cardholder',		0, qr/^nameOnCard$/, ],
	[ 'type',		0, qr/^cardType$/, ],
	[ 'ccnum',		0, qr/^cardNumber$/, ],
	[ 'cvv',		0, qr/^security_code$/, ],
	[ 'pin',		0, qr/^pin$/, ],
	[ 'bank',		0, qr/^issuingBank$/, ],
	[ 'expiry',		0, qr/^expires$/, 	{ func => sub { return date2monthYear($_[0]) } } ],
	[ '_issuedata',		0, qr/^issueDate$/, ],

    ]},

    database =>			{ textname => 'PV::Database', fields => [
	[ 'hostname',		0, qr/^server_address$/, ],
	[ 'port',		0, qr/^port$/, ],
	[ 'username',		0, qr/^username$/, ],
	[ 'password',		0, qr/^password$/, ],
	[ 'database',		0, qr/^database$/, ],
    ]},

    driverslicense =>		{ textname => 'SN::DriverLicense', fields => [
	[ 'country',		0, qr/^country$/, ],
	[ 'number',		0, qr/^driverLicenseNumber$/, ],
	[ '_expires',		0, qr/^expires$/, ],

	[ '_firstname',		0, 'firstName', ],	# see 'Fixup: combine names'
        [ '_lastname',		0, 'lastName', ],	# see 'Fixup: combine names'
        [ 'fullname',		0, 'First + Last', ],	# see 'Fixup: combine names'; input never matches
    ]},

    emailaccount =>		{ textname => 'PV::EmailAccount', type_out => 'email', fields => [
	[ 'smtp_username',	0, qr/^username$/, ],
	[ 'smtp_password',	0, qr/^password$/, ],
	[ 'smtp_server',	0, qr/^smtp_server$/, ],
	[ 'smtp_port',		0, qr/^port$/, ],
	[ '_type',		0, qr/^type$/, ],
    ]},

    estateplan =>		{ textname => 'SN::EstatePlan', type_out => 'note', fields => [
	[ '_executor',		0, qr/^executor$/,  		{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'executor' ] } ],
	[ '_attorney',		0, qr/^attorney$/, 	 	{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'attorney' ] } ],
	[ '_trustee',		0, qr/^trustee$/, 	 	{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'trustee' ] } ],
	[ '_location',		0, qr/^location_of_documents$/, { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'document location' ] } ],
    ]},

    frequentflyer =>		{ textname => 'SN::FrequentFlyer', type_out => 'rewards', fields => [
	[ 'company_name',	0, qr/^airline$/, ],
	[ 'membership_no',	0, qr/^frequent_flyer_number$/, ],
	[ 'customer_service_phone',	0, qr/^phoneNumber$/, ],
	[ '_status_level',	0, qr/^status_level$/, { custfield => [ $Utils::PIF::sn_extra, $Utils::PIF::k_string, 'status level' ] } ],
    ]},

    healthinsurance =>		{ textname => 'SN::HealthInsurance', type_out => 'membership', fields => [
	[ 'membership_no',	0, qr/^memberID$/, ],
	[ 'org_name',		0, qr/^insurance_company$/, ],
	[ '_group_number',	0, qr/^group_number$/, 	    { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'group number' ] }],
	[ '_prescription_plan',	0, qr/^prescription_plan$/, { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'prescription plan' ] }],
    ]},

    hotelrewards =>		{ textname => 'SN::HotelRewards', type_out => 'rewards', fields => [
	[ 'company_name',	0, qr/^hotel$/, ],
	[ 'membership_no',	0, qr/^membership_number$/, ],
	[ 'customer_service_phone',	0, qr/^phoneNumber$/, ],
	[ '_status_level',	0, qr/^status_level$/, { custfield => [ $Utils::PIF::sn_extra, $Utils::PIF::k_string, 'status level' ] } ],
    ]},

    identity =>			{ textname => 'PI::Names', fields => [
	[ 'firstname',		0, qr/^firstName$/, ],
	[ 'initial',		0, qr/^middleName$/, ],
	[ 'lastname',		0, qr/^lastName$/, ],
    ]},

    instantmessenger =>		{ textname => 'PV::InstantMessenger', type_out => 'note', fields => [
	[ '_application',	0, qr/^application$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'application' ] } ],
	[ '_server',		0, qr/^server_address$/, { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'server' ] } ],
	[ '_port',		0, qr/^port$/, 		 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'port' ] } ],
	[ '_username',		0, qr/^username$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'username' ] } ],
	[ '_password',		0, qr/^password$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_concealed, 'password' ] } ],
    ]},

    insurance =>		{ textname => 'SN::Insurance', type_out => 'membership', fields => [
	[ 'org_name',		0, qr/^insurance_company$/, ],
	[ 'membership_no',	0, qr/^memberID$/, ],
	[ '_policy_number',	0, qr/^policy_number$/,     { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'policy number' ] }],
	[ '_type',		0, qr/^type$/,     { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'type' ] }],
	[ '_agent',		0, qr/^agent$/, 	    { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'agent' ] }],
	[ 'phone',		0, qr/^phoneNumber$/, ],
	[ '_renewal_date',	0, qr/^renewal_date$/, ],
    ]},

    memberid =>			{ textname => 'SN::MemberIDs', type_out => 'membership', fields => [
	[ 'membership_no',	0, qr/^memberID$/, ],
	[ '_firstname',		0, 'firstName', ],	# see 'Fixup: combine names'
        [ '_lastname',		0, 'lastName', ],	# see 'Fixup: combine names'
        [ 'member_name',	0, 'First + Last', ],	# see 'Fixup: combine names'; input never matches
    ]},

    passport =>			{ textname => 'SN::Passport', fields => [
	[ 'number',		0, qr/^passportNumber$/, ],
	[ 'issuing_country',	0, qr/^placeOfIssue$/, ],
	[ 'nationality',	0, qr/^nationality$/, ],
	[ '_expires',		0, qr/^expires$/, ],
	[ '_issuedate',		0, qr/^issueDate$/, ],
	[ '_dateofbirth',	0, qr/^dateOfBirth$/, ],
	[ '_firstname',		0, 'firstName', ],	# see 'Fixup: combine names'
        [ '_lastname',		0, 'lastName', ],	# see 'Fixup: combine names'
        [ 'fullname',		0, 'First + Last', ],	# see 'Fixup: combine names'; input never matches
    ]},

    prescription =>             { textname => 'SN::Prescription', type_out => 'note', fields => [
	[ '_medicine',		0, qr/^medicine$/,		{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'medicine' ] }],
	[ '_prescriptionnum',	0, qr/^prescription_number$/,	{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'prescription number' ] }],
	[ '_doctor',		0, qr/^doctor$/,		{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'doctor' ] }],
	[ '_doctor_phone',	0, qr/^doctor_phone$/,		{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'doctor_phone' ] }],
	[ '_pharmacy',		0, qr/^pharmacy$/,		{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'pharmacy' ] }],
	[ '_pharmacy_phone',	0, qr/^pharmacy_phone$/,	{ custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'pharmacy_phone' ] }],
    ]},

    server =>			{ textname => 'PV::Server', fields => [
	[ 'username',		0, qr/^username$/, ],
	[ 'password',		0, qr/^password$/, ],
	[ 'url',		0, qr/^server_address$/, ],
	[ '_port',		0, qr/^server_port$/, ],
	[ '_application',	0, qr/^port$/, ],
	[ '_totp',              0, qr/^totp$/,         { custfield => [ $Utils::PIF::sn_details, $Utils::PIF::k_totp, 'totp' ] }  ],
    ]},

    socialsecurity =>		{ textname => 'SN::SocialSecurity', fields => [
	[ 'number',		0, qr/^ssn$/, ],
	[ '_firstname',		0, 'firstName', ],	# see 'Fixup: combine names'
        [ '_lastname',		0, 'lastName', ],	# see 'Fixup: combine names'
        [ 'name',		0, 'First + Last', ],	# see 'Fixup: combine names'; input never matches
    ]},

    softwarelicense =>		{ textname => 'SN::SoftwareLicense', type_out => 'software', fields => [
	[ 'product_version',	0, qr/^version$/, ],
	[ 'reg_code',		0, qr/^license_key$/, ],
	[ 'publisher_name',	0, qr/^publisher$/, ],
	[ 'order_number',	0, qr/^order_number$/, ],
	[ 'retail_price',	0, qr/^price$/, ],
	[ '_numberoflicenses',	0, qr/^number_of_licenses$/, ],
	[ '_purchase_date',	0, qr/^purchase_date$/, ],
	[ '_support_through',	0, qr/^support_through$/, ],
    ]},

    sshkeys =>			{ textname => 'PV::SSHKey', type_out => 'note', fields => [
	[ '_server_address',	0, qr/^server_address$/, { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'server address' ] } ],
	[ '_port',		0, qr/^port$/, 		 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'port' ] } ],
	[ '_passphrase',	0, qr/^passphrase$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_concealed, 'passphrase' ] } ],
	[ '_format',		0, qr/^format$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'format' ] } ],
	[ '_bit_strength',	0, qr/^bit_strength$/, 	 { custfield => [ $Utils::PIF::sn_main, $Utils::PIF::k_string, 'bit strength' ] } ],
    ]},

    website =>			{ textname => 'PV::Website', type_out =>'login', fields => [
	[ 'username',		0, qr/^username$/, ],
	[ 'password',		0, qr/^password$/, ],
	[ 'url',		0, qr/^url$/, ],
	[ '_name',		0, qr/^name$/, ],
	[ '_favorite',		0, qr/^favorite$/, ],
	[ '_totp',		0, qr/^totp$/, ],
    ]},

    wifi =>			{ textname => 'PV::WiFi', type_out => 'wireless', fields => [
	[ 'airport_id',		0, qr/^ssid$/, ],
	[ 'wireless_password',	0, qr/^password$/, ],
	[ 'wireless_security',	0, qr/^encryption$/, ],
	[ '_authentication',	0, qr/^authentication$/, ],
	[ '_fips_mode',		0, qr/^fips_mode$/, ],
	[ '_fips_keytype',	0, qr/^key_type$/, ],
    ]},

    password =>			{ textname => 'password', fields => [
	[ 'password',		0, qr/^password$/, ],
    ]},

    note =>			{ textname => 'notes', fields => [
    ]},
);

$DB::single = 1;					# triggers breakpoint when debugging

sub do_init {
    return {
	'specs'		=> \%card_field_specs,
	'imptypes'  	=> undef,
        'opts'          => [
	      		     [ q{      --dumpcats           # print the export's categories and field quantities },
			       'dumpcats' ],
	      		     [ q{      --appendsubtitle     # append the subtitle to an item's title },
			       'appendsubtitle' ],
			   ]
    }
}

sub do_import {
    my ($file, $imptypes) = @_;
    my %Cards;

    my $data = slurp_file($file, 'utf8');

    my $n;
    if ($data =~ /^\{/ and $data =~ /\}$/) {
	$n = process_json(\$data, \%Cards, $imptypes);
    }

    summarize_import('item', $n - 1);
    return \%Cards;
}

sub process_json {
    my ($data, $Cards, $imptypes) = @_;
    my %Folders;

    my $decoded = decode_json Encode::encode('UTF-8', $$data);

    exists $decoded->{'items'} or
	bail "Unable to find any items in the Password Boss JSON export file";

    # Process any folders
    for my $folder ( exists $decoded->{'folders'} ? @{$decoded->{'folders'}} : () ) {
	$Folders{$folder->{'id'}} = { name => $folder->{'name'} };
	$Folders{$folder->{'id'}}{'parent'} = $folder->{'parent'} 	if exists $folder->{'parent'};
    }

    if ($main::opts{'dumpcats'}) {
	dumpcats($decoded);
	exit;
    }

    my $n = 1;

    for my $entry (@{$decoded->{items}}) {
	my (%cmeta, @fieldlist);

	my $origtype = join '::', $entry->{'secure_item_type_name'}, $entry->{'type'};
	delete $entry->{'secure_item_type_name'};
	delete $entry->{'type'};
	my $itype = find_card_type($origtype);
	debug "Processing type: $itype ($origtype)";

	$cmeta{'title'} = $entry->{'name'} // 'Untitled';
	delete $entry->{'name'};

	if ($main::opts{'appendsubtitle'} and exists $entry->{'subtitle'}) {
	    $cmeta{'title'} .= ' - ' . $entry->{'subtitle'};
	    delete $entry->{'subtitle'};
	}

	@{$cmeta{'tags'}} = @{$entry->{'tags'}}		if @{$entry->{'tags'}};
	delete $entry->{'tags'};

	# Handle folder tree
	if (exists $entry->{'folder'}) {
	    push @{$cmeta{'tags'}}, getFolderPath(\%Folders, $entry->{'folder'});
	    delete $entry->{'folder'};
	}

	if ($origtype eq 'PV::Website') {
	    # delete superfluous login_url
	    if (exists $entry->{'identifiers'}{'url'} and $entry->{'identifiers'}{'url'} eq $entry->{'login_url'}) {
		delete $entry->{'login_url'};
	    }
	}


	if (exists $entry->{'color'}) {
	    push @{$cmeta{'tags'}}, 'Colors/'. $entry->{'color'}	 unless grep { 'color' eq $_ } @ignoredFields;
	    delete $entry->{'color'};
	}

	# identifiers section
	#
	for my $identkey (keys %{$entry->{'identifiers'}}) {
	    my $identifiers = $entry->{'identifiers'};

	    next if grep { $identkey eq $_ } @ignoredIdentifiers;

	    if ($identkey eq 'notes') {
		push @{$cmeta{'notes'}}, $identifiers->{'notes'};
	    }

	    elsif ($identkey eq 'custom_fields') {
		for my $custfield (@{$identifiers->{'custom_fields'}}) {
		    next if $custfield->{'value'} eq '';
		    my $name = $custfield->{'name'} eq '' ? 'unnamed' : $custfield->{'name'};
		    push @fieldlist, [ $name => $custfield->{'value'} ]
		}
	    }

	    elsif ($identkey eq 'favorite') {
		push @{$cmeta{'tags'}}, 'Favorite'		if $identifiers->{'favorite'} eq '1';
	    }

	    elsif ($identkey eq 'name' and $cmeta{'title'} eq $identifiers->{'name'}) {
		next;
	    }

	    else {
		# Category specific fields
		my $key = $identkey;

		# avoid collisions
		if ($identkey eq 'port' and $itype eq 'server') {
		    $key = 'server_port'
		}

		if (defined $identifiers->{$key} and $identifiers->{$key} ne '') {
		    push @fieldlist, [ $key => $identifiers->{$key} ]		
		}
	    }
	}
	delete $entry->{'identifiers'};

	# keep track of the original type / subtype for all but a generic Note
	if ($itype eq 'note' and $origtype ne 'SN::GenericNote') {
	    push @{$cmeta{'notes'}}, $origtype;
	}

	for my $field (keys %$entry) {
	    push @fieldlist, [ $field => $entry->{$field} ]	unless grep { $field eq $_ } @ignoredFields;
	    delete $entry->{$field};
	}

	# Fixup: combine names
	if ($itype =~ /^driverslicense|memberid|passport|socialsecurity$/) {
            my @found = grep { $_->[0] eq 'firstName' or $_->[0] eq 'lastName' } @fieldlist;
            if (@found == 2) {
                push @fieldlist, [ 'First + Last' =>
			$found[0][0] eq 'firstName' ?
			    myjoin(' ', $found[0][1], $found[1][1]) :
			    myjoin(' ', $found[1][1], $found[0][1])
		    ];
                debug "\t\tfield added: $fieldlist[-1][0] -> $fieldlist[-1][1]";
            }
        }

	if (do_common($Cards, \@fieldlist, \%cmeta, $imptypes, $itype)) {
	    $n++;
	}
    }

    return $n;
}

sub dumpcats {
    my $decoded = shift;

    my %cats;

    # Get the section name and fields in each entry.
    for my $entry (@{$decoded->{'items'}}) {
	$cats{join '::', $entry->{'secure_item_type_name'}, $entry->{'type'}}++;
    }

    for my $key (sort keys %cats) {
	printf "%s (%d)\n", $key, $cats{$key};
    }
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

sub getFolderPath {
    my ($Folders, $fid) = @_;
    my @folderpath;

    while ($fid) {
	unshift @folderpath, $Folders->{$fid}{'name'};
	if (exists $Folders->{$fid}{'parent'}) {
	    $fid = $Folders->{$fid}{'parent'}		
	}
	else {
	    $fid = undef;
	}
    }
    return join "/", @folderpath;
}

#  "expires" : "2022-03-01T00:00:00.000Z"
sub parse_date_string {
    local $_ = $_[0];

    my ($datestr,undef) = split /T/, $_;
    return undef unless $datestr;

    if (my $t = Time::Piece->strptime($datestr, "%Y-%m-%d")) {
	return $t;
    }

    return undef;
}

sub date2monthYear {
    my $t = parse_date_string(@_);
    return defined $t && defined $t->year ? sprintf("%d%02d", $t->year, $t->mon) : '';
}
1;
