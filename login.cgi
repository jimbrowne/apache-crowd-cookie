#!/usr/bin/perl

# This is an example how to create a Atlassian Crowd login screen
# using perl.  After you use this login, you get Single Sign On and
# can access also other applications using Crowd

# Copyright 2008: Marko Nordberg 2008-02-20
# Permission is granted to use this free for any usage.

# Copyright 2010: Jim Browne, assigned to Atlassian
# Perl 5 (or later) license

# Modes of operation:
#
# Logout param present, delete cookie
# Valid user/password params present:
#   If "loc" param present, set cookie and redirect to "loc" URL
#   If no "loc" param present, set cookie and redirect to self
# Valid cookie present: Present logout option
# Invalid cookie present, no cookie present, or invalid user/password params:
#  Present login option

use strict;
use CGI qw/:standard/;
use CGI::Cookie;

# Comment to disable debug trace
#use SOAP::Lite +trace => qw (debug);
# Comment to disable error messages to browser
#use CGI::Carp qw(fatalsToBrowser);

use Atlassian::Crowd qw( :all );

# Namespace
my $NS = "urn:SecurityServer";

# namespace attribute used in SOAP call creation.
my $XMLNS = 'http://authentication.integration.crowd.atlassian.com';

# Comment this block to disable debug
# BEGIN {
#     use CGI::Carp qw(carpout);
#     open(LOG, ">>/tmp/crowd_perldemo_soap.log") or die("Unable to open file: $!\n");
#     carpout(\*LOG);
# }

# Modify these to match your configuration
my $serverURL = 'http://localhost:8095/crowd/services/SecurityServer';
my $app_name = 'apache';
my $app_credential = 'PUT_YOUR_APACHE_APPLICATION_CREDENTIAL_HERE';

my $status;
my @groups;
my $cookie;
my $apptoken;
my $principal_token;

# X_FORWARDED_FOR is missing from these valiation factors, so this may
# not work # if behind a proxy
my %validation_factors = (REMOTE_ADDRESS => $ENV{REMOTE_ADDR}, USER_AGENT => http('User-Agent'));

my %request_cookies = fetch CGI::Cookie;
my $sent_cookie = $request_cookies{'crowd.token_key'}->value
    if (defined $request_cookies{'crowd.token_key'});
my $sent_cookie_status;
my $logged_in = 0;

$apptoken = Atlassian::Crowd::authenticate_app($serverURL, $app_name,
					       $app_credential);

if ($sent_cookie && $apptoken) {
    $sent_cookie_status = "Cookie received $sent_cookie";
    if (isValidPrincipalToken($serverURL, $app_name, $apptoken, $sent_cookie,http('User-Agent'),$ENV{REMOTE_ADDR},0,0)) {
	$sent_cookie_status .= " <strong>VALID</strong>";
	$logged_in = 1;
    } else {
	$sent_cookie_status .= " <strong>INVALID</strong>";
    }
} else {
    $sent_cookie_status = "No crowd.token_key cookie seen in request";
}

if (param('username') and param('password')) {
    if ($apptoken) {
	if ($principal_token = authenticate_principal($serverURL, $app_name, $apptoken, param('username'), param('password'), \%validation_factors)) {
	    $status = 'OK';
	    @groups = Atlassian::Crowd::find_group_memberships($serverURL, $app_name, $apptoken, param('username')) or die "Error in find_group_memberships()";
	    $cookie = new CGI::Cookie(-name    =>  'crowd.token_key', -value   =>  "$principal_token");
	} else {
	    $status = "Invalid username or password";
	}
    } else {
	$status = "Application name or credential is not valid";
    }
}

if (param('logout')) {
    $cookie = new CGI::Cookie(-name =>  'crowd.token_key',
			      -expires   =>  "-1M");
    print header(-cookie=>$cookie), start_html('Logged Out');
    print "You have been logged out.<p>\n";
    print a({-href=>url()}, "Log in");
    end_html;
} elsif ($status eq 'OK') {
    print header(-cookie=>$cookie);
    my $dest = url();
    $dest = param('loc') if (defined(param('loc')));
    print start_html(-head=> meta(
			  {-http_equiv=>'REFRESH',-content=>"0;" . $dest}
		     )
	);
    print end_html;
} else {
    print header(-cookie=>$cookie),
    start_html('Login'),
    h1('Login'),
    h2({-style=>'Color: red;'}, $status);
    print "Groups: ". join (', ', @groups) . "<p>\n" if @groups;
    print "Token: $principal_token<p>\n" if $principal_token;
    print "$sent_cookie_status<p>\n";
    print start_multipart_form(-action => url()), "<table>";
    if (!$logged_in) {
	print "\n<tr><td>Username: <td>",textfield('username'),
	"\n<tr><td>Password: <td>", password_field('password');
	print hidden('loc',param('loc')) if defined(param('loc'));
    } else {
	print checkbox(-name=>'logout', -label=>'Log Out');
    }
    print "</table>\n", 
    p, submit, end_form, p,
    end_html;
}
# ---------------------------------------------------------------------------

# authenticate a principal. Returns a principal token on successfull login, and
# undef on failure.
sub authenticate_principal {
        
        my ($serverURL, $app_name, $appToken, $principal_name, $principal_credential, $validation_factors) = @_;
        
        if(!defined($appToken)) {
                return undef;
        }
        
	my @validation_factor_params;
	while (my ($name, $value) = each %$validation_factors) {
	    push @validation_factor_params, \SOAP::Data->value(
		SOAP::Data->name('name' => $name)->type('string')->attr({xmlns => $XMLNS}),
		SOAP::Data->name('value' => $value)->type('string')->attr({xmlns => $XMLNS}),
		)
		
	}
	@validation_factor_params = undef unless @validation_factor_params;

        my $principal_method = SOAP::Data->name('authenticatePrincipal')
        ->uri($NS);
        
        my @principal_params = (
        SOAP::Data->name('in0' =>
                \SOAP::Data->value(
                                SOAP::Data->name('name' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
                                SOAP::Data->name('token' => $appToken)->attr({xmlns => $XMLNS}),
        )),
        SOAP::Data->name('in1' =>
        \SOAP::Data->value(
                SOAP::Data->name('application' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
                SOAP::Data->name('credential' => \SOAP::Data->value(
                        SOAP::Data->name('credential' => $principal_credential)->type('string')))->attr({xmlns => $XMLNS}),
                        SOAP::Data->name('name' => $principal_name)->type('string')->attr({xmlns => $XMLNS}),
                        SOAP::Data->name('validationFactors' => \@validation_factor_params)->attr({xmlns => $XMLNS})
                        ))
        );
        
        my $principal_som = Atlassian::Crowd::make_soap_call($serverURL, 'authenticatePrincipal', @principal_params);
        
        if (!defined($principal_som)) {
                return undef;
        } elsif ($principal_som->fault) { # will be defined if Fault element is in the message
                return undef;
        } else {
                my $principalToken = $principal_som->valueof('//authenticatePrincipalResponse/out');

                if(defined($principalToken)) {
                        return $principalToken;
                } else {
                        return undef;
                }
        }
        return undef;
}

# ---------------------------------------------------------------------------


# Validate principal token
sub isValidPrincipalToken {
    my ($serverURL, $app_name, $apptoken, $userToken,$userAgent,$remote_address,$apache_address,$useproxy) = @_;
    
    my $principal_method = SOAP::Data->name('isValidPrincipalToken');
    
    my $validationFactor1 = SOAP::Data->name('ValidationFactor' =>
					     \SOAP::Data->value(
						 SOAP::Data->name('name' => "USER_AGENT")->type('string')->attr({xmlns => $XMLNS}),
						 SOAP::Data->name('value' => $userAgent)->type('string')->attr({xmlns => $XMLNS})
					     )
	);
    
    my $validationFactor2;
    my $validationFactor3;
    
    my $in2_message;
    
    if(defined $useproxy) {
	$validationFactor2 = SOAP::Data->name('ValidationFactor' =>
					      \SOAP::Data->value(
						  SOAP::Data->name('name' => "REMOTE_ADDRESS")->type('string')->attr({xmlns => $XMLNS}),
						  SOAP::Data->name('value' => $apache_address)->type('string')->attr({xmlns => $XMLNS})
					      )
	    );
	
	$validationFactor3 = SOAP::Data->name('ValidationFactor' =>
					      \SOAP::Data->value(
						  SOAP::Data->name('name' => "X-Forwarded-For")->type('string')->attr({xmlns => $XMLNS}),
						  SOAP::Data->name('value' => $remote_address)->type('string')->attr({xmlns => $XMLNS})
					      )
	    );
	
	$in2_message = SOAP::Data->name( 'in2' => \SOAP::Data->value($validationFactor1,$validationFactor2,$validationFactor3));
	
    } else {
	$validationFactor2 = SOAP::Data->name('ValidationFactor' =>
					      \SOAP::Data->value(
						  SOAP::Data->name('name' => "REMOTE_ADDRESS")->type('string')->attr({xmlns => $XMLNS}),
						  SOAP::Data->name('value' => $remote_address)->type('string')->attr({xmlns => $XMLNS})
					      )
	    );
	$in2_message = SOAP::Data->name( 'in2' => \SOAP::Data->value($validationFactor1,$validationFactor2));
    }
    
    my @principal_params = (
	SOAP::Data->name(
	    'in0' => \SOAP::Data->value( SOAP::Data->name( 'name' => $app_name )->type('string')->attr( { xmlns => $XMLNS } ), SOAP::Data->name( 'token' => $apptoken )->attr( { xmlns => $XMLNS } ), )
	),
	SOAP::Data->name( 'in1' => $userToken )->type('string')->attr( { xmlns => $XMLNS } ),
	$in2_message
	#SOAP::Data->name( 'in2' =>
	# \SOAP::Data->value(
	#   		$validationFactor1,
	#			$validationFactor2
	#  )
	#)
	);
    
    
    my $response = Atlassian::Crowd::make_soap_call( $serverURL, 'isValidPrincipalToken', @principal_params );
    
    if (!defined($response)) {
	return undef;
    } elsif ($response->fault) {
	return undef;
    }
    
    my $isvalid = $response->valueof('//isValidPrincipalTokenResponse/out');
    
    if(!defined($isvalid) || $isvalid eq "false") {
	return undef;
    }
    
    return 1;
    
}
