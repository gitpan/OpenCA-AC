## OpenCA::AC.pm 
##
## Copyright (C) 2000-2003 Michael Bell <michael.bell@web.de>
## All rights reserved.
##
##    This library is free software; you can redistribute it and/or
##    modify it under the terms of the GNU Lesser General Public
##    License as published by the Free Software Foundation; either
##    version 2.1 of the License, or (at your option) any later version.
##
##    This library is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##    Lesser General Public License for more details.
##
##    You should have received a copy of the GNU Lesser General Public
##    License along with this library; if not, write to the Free Software
##    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##

use strict;

package OpenCA::AC;

use XML::Twig;
use OpenCA::TRIStateCGI;
use OpenCA::Tools;
use OpenCA::Log::Message;

use FileHandle;
our ($STDERR, $STDOUT);
$STDOUT = \*STDOUT;
$STDERR = \*STDERR;

our ($errno, $errval);

($OpenCA::AC::VERSION = '$Revision: 1.30 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
                DEBUG_CT  => 0,
                debug_fd  => $STDOUT,
                ## debug_msg => ()
               };

    bless $self, $class;

    my $keys = { @_ };
    ## FIXME: this is really dangerous
    $self->{configfile}  = $keys->{CONFIG};
    $self->{CRYPTO}      = $keys->{CRYPTO};
    $self->{cryptoShell} = $self->{CRYPTO}->getToken;
    $self->{db}          = $keys->{DB};
    $self->{cgi}         = $keys->{CGI};
    $self->{DEBUG}       = 1 if ($keys->{DEBUG});
    $self->{log}         = $keys->{LOG};
    $self->{output_func} = $keys->{OUTPUT_FUNCTION};
    $self->{gettext}     = $keys->{GETTEXT};
    $self->{session}     = $keys->{SESSION};
    $self->{cache}       = $keys->{CACHE};

    print "Content-type: text/html\n\n" if ($self->{DEBUG});

    $self->{tools} = new OpenCA::Tools;

    if (not $self->{log}) {
        $self->setError (6211005, "There is no log facility defined.");
        return undef;
    }

    if ($self->{configfile} eq "") {
        $self->setError (6211010, "The configfile was not specified.");
        return undef;
    }

    return undef if (not $self->checkAccess ());

    return $self;
}

sub setError {
    my $self = shift;

    if (scalar (@_) == 4) {
        my $keys = { @_ };
        $self->{errval} = $keys->{ERRVAL};
        $self->{errno}  = $keys->{ERRNO};
    } else {
        $self->{errno}  = $_[0];
        $self->{errval} = $_[1];
    }
    $errno  = $self->{errno};
    $errval = $self->{errval};

    $self->{journal}->{errno}   = $self->{errno};
    $self->{journal}->{errval}  = $self->{errval};
    $self->{journal}->{message} = "";
    foreach my $msg (@{$self->{debug_msg}}) {
        $self->{journal}->{message} .= $msg."\n";
    }

    if ($self->{errno} == 6211005) {
        print $STDERR "OpenCA Log error: ".$self->{errno}.": ".$self->{errval}."\n";
    } else {
        $self->{log}->addMessage (OpenCA::Log::Message->new (HASHREF => $self->{journal}));
    }

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub checkAccess {

    my $self = shift;

    $self->{journal}->{CLASS}   = "access_control";
    $self->{journal}->{LEVEL}   = "critical";
    $self->{journal}->{message} = "";

    $self->getModule();
    return undef if (not $self->checkChannel());
    return undef if (not $self->checkIdent());
    return undef if (not $self->checkACL());
    return undef if (not $self->initToken());

    $self->{journal}->{LEVEL}   = "info";
    $self->{log}->addMessage (OpenCA::Log::Message->new (HASHREF => $self->{journal}));

    return 1;
}

sub debug {

    my $self = shift;
    if ($_[0]) {
        $self->{debug_msg}[scalar @{$self->{debug_msg}}] = $_[0];
        $self->debug () if ($self->{DEBUG});
    } else {
        ## FIXME: is there a better way?
        if (not $self->{DEBUG_CT})
        {
            $self->{DEBUG_CT} = 1;
            print "Content-type: text/html\n\n";
        }
        my $msg;
        foreach $msg (@{$self->{debug_msg}}) {
            $msg =~ s/ /&nbsp;/g;
            my $oldfh = select $self->{debug_fd};
            print $msg."<br>\n";
            select $oldfh;
        }
        $self->{debug_msg} = ();
    }

}

#############################################################################
##                         check the channel                               ##
#############################################################################

sub checkChannel {

    my $self = shift;

    $self->debug ("Checking the channel ...");

    $self->debug ("    loading configuration ...");

    my $config_channel_type         = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/type'
                                                                );
    my $config_security_protocol    = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/protocol'
                                                                );
    my $config_source               = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/source'
                                                                );
    my $config_asymmetric_cipher    = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/asymmetric_cipher'
                                                                );
    my $config_asymmetric_keylength = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/asymmetric_keylength'
                                                                );
    my $config_symmetric_cipher     = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/symmetric_cipher'
                                                                );
    my $config_symmetric_keylength  = $self->{cache}->get_xpath (
                                          FILENAME => $self->{configfile},
                                          XPATH    => 'access_control/channel/symmetric_keylength'
                                                                );

    $config_asymmetric_keylength = 0 if (not $config_asymmetric_keylength);
    $config_symmetric_keylength  = 0 if (not $config_symmetric_keylength);

    $self->debug ("        channel type ... ${config_channel_type}");
    $self->debug ("        security protocol ... ${config_security_protocol}");
    $self->debug ("        source ... ${config_source}");
    $self->debug ("        asymmetric cipher ... ${config_asymmetric_cipher}");
    $self->debug ("        asymmetric keylength ... ${config_asymmetric_keylength}");
    $self->debug ("        symmetric cipher ... ${config_symmetric_cipher}");
    $self->debug ("        asymmetric keylength ... ${config_symmetric_keylength}");

    $self->debug ("    loading channel data ... ");

    $self->{channel}->{type}                 = "";
    $self->{channel}->{security_protocol}    = "";
    $self->{channel}->{source}               = "";
    $self->{channel}->{asymmetric_cipher}    = "";
    $self->{channel}->{asymmetric_keylength} = 0;
    $self->{channel}->{symmetric_cipher}     = "";
    $self->{channel}->{symmetric_keylength}  = 0;
    $self->{journal}->{channel} = $self->{channel};

    ## looks senseless but good for the future
    if ($ENV{SERVER_SOFTWARE} =~ /mod_ssl/)
    {
        $self->{channel}->{type} = "mod_ssl";
    } else {
        $self->{channel}->{type} = "mod_ssl";
    }

    $self->debug ("        channel type ... ".$self->{channel}->{type});

    if ($self->{channel}->{type} =~ /mod_ssl/) {
        if ($ENV{HTTPS} =~ /^on$/i) {
            $self->{channel}->{security_protocol} = "ssl";
            if ($self->{channel}->{security_protocol} eq "ssl") {
                $self->{channel}->{symmetric_cipher}     = $ENV{SSL_CIPHER};
                $self->{channel}->{symmetric_keylength}  = $ENV{SSL_CIPHER_USEKEYSIZE};
            }
        } else {
            $self->{channel}->{security_protocol} = "http";
        }
        $self->{channel}->{source} = $ENV{REMOTE_ADDR};
    }

    $self->debug ("    check channel data ...");

    if ($self->{channel}->{type} =~ /${config_channel_type}/) {
        $self->debug ("        channel type ... ok");
    } else {
        $self->setError (6251023,
                         "Aborting connection - you are using a wrong channel (".
                         $self->{channel}->{type}.")");
        return undef;
    }
    if ($self->{channel}->{security_protocol} =~ /${config_security_protocol}/) {
        $self->debug ("        security protocol ... ok");
    } else {
        $self->setError (6251026,
                         "Aborting connection - you are using a wrong security protocol (".
                         $self->{channel}->{security_protocol}.")");
        return undef;
    }
    if ($self->{channel}->{source} =~ /${config_source}/) {
        $self->debug ("        source ... ok");
    } else {
        $self->setError (6251029,
                         "Aborting connection - you are using the wrong computer (".
                         $self->{channel}->{source}.")");
        return undef;
    }
    if ($self->{channel}->{asymmetric_cipher} =~ /${config_asymmetric_cipher}/) {
        $self->debug ("        asymmetric cipher ... ok");
    } else {
        $self->setError (6251033,
                         "Aborting connection - you are using a wrong asymmetric cipher (".
                         $self->{channel}->{asymmetric_cipher}.")");
        return undef;
    }
    if ($self->{channel}->{asymmetric_keylength} >= ${config_asymmetric_keylength}) {
        $self->debug ("        asymmetric keylength ... ok");
    } else {
        $self->setError (6251036,
                         "Aborting connection - you are using a too short asymmetric keylength (".
                         $self->{channel}->{asymmetric_keylength}.")");
        return undef;
    }
    if ($self->{channel}->{symmetric_cipher} =~ /${config_symmetric_cipher}/) {
        $self->debug ("        symmetric cipher ... ok");
    } else {
        $self->setError (6251039,
                         "Aborting connection - you are using a wrong symmetric cipher (".
                         $self->{channel}->{symmetric_cipher}.")");
        return undef;
    }
    if ($self->{channel}->{symmetric_keylength} >= ${config_symmetric_keylength}) {
        $self->debug ("        symmetric keylength ... ok");
    } else {
        $self->setError (6251043,
                         "Aborting connection - you are using a too short symmetric keylength (".
                         $self->{channel}->{symmetric_keylength}.")");
        return undef;
    }

    $self->debug ("Channel is ok");
    return 1;

}

########################################################################
##                          identify the user                         ##
########################################################################

sub checkIdent {

    my $self = shift;

    $self->debug ("Starting authentication ... ");

    $self->{ident}->{type} = $self->{cache}->get_xpath (
                                 FILENAME => $self->{configfile},
                                 XPATH    => 'access_control/login/type'
                                                       );
    ## return 1 if ($self->{ident}->{type} =~ /^none$/i);

    $self->debug ("    channel type ... ".$self->{channel}->{type});

    if ($self->{channel}->{type} eq "mod_ssl") {
        ##
    } else {
        $self->setError (6271013, "You use an unsupported channel (".$self->{channel}->{type}.").");
        return undef;
    }

    if (not $self->getSession ()) {
        if (not $self->login ()) {
            return undef;
        } else {
            my $h = $self->{session}->start();
            ## set the correct values after a successful login
            $self->{session}->setParam ('name', $self->{ident}->{name});
            $self->{session}->setParam ('valid', '1');
            $self->{journal}->{login}->{name} = $self->{ident}->{name};
            return $h;
        }
    } else {
        return $self->stopSession if ($self->{cgi}->param ('cmd') eq 'logout');
        return $self->{session}->update();
    }

    ## unexpected error because never reached
    return undef;
}

sub getSession {
    my $self = shift;
    $self->debug ("    Try to get a session ...");

    return undef if (not $self->{session}->load());

    ## name can be a false value
    ## valid is a protection against expired sessions
    $self->{ident}->{name}          = $self->{session}->getParam("name");
    $self->{ident}->{valid}         = $self->{session}->getParam("valid");
    $self->{ident}->{prepare_ident} = $self->{session}->getParam("prepare_ident");

    if (not $self->{ident}->{valid}) {
        $self->{session}->stop();
        return undef;
    }
    $self->{journal}->{login}->{name} = $self->{ident}->{name};
    $self->{journal}->{login}->{prepare_ident} = "TRUE";
    $self->{journal}->{session_id}    = $self->{session}->getID();
    $self->{journal}->{session_type}  = "cookie";

    return undef if ($self->{ident}->{prepare_ident});
    delete $self->{journal}->{login}->{prepare_ident};

    return 1;
}

sub login {
    my $self = shift;
    $self->debug ("    Try to login ...");

    if ($self->{ident}->{type} =~ /^none$/i) {
        $self->debug ("        type ... none");
        $self->debug ("        identification disabled");
        $self->{journal}->{login}->{type} = "none";
        return 1;
    } elsif ($self->{ident}->{type} =~ /^passwd$/i) {
        $self->debug ("        type ... passwd");
        $self->{journal}->{login}->{type} = "passwd";
        if ($self->{cgi}->param ('login')) {
            $self->debug ("        credentials ... present");
            $self->{ident}->{name} = $self->{cgi}->param ('login');
            $self->debug ("        name ... ".$self->{ident}->{name});
            if ($self->{cache}->get_xpath (
                    FILENAME => $self->{configfile},
                    XPATH    => 'access_control/login/database'
                                          ) =~ /^internal$/i) {
                $self->debug ("        database ... internal");

                my $user = undef;
                my $name = undef;
                my $algorithm = undef;
                my $digest = undef;

                ## scan for login
                my $user_count = $self->{cache}->get_xpath_count (
                                FILENAME => $self->{configfile},
                                XPATH    => 'access_control/login/passwd/user');
                for (my $i=0; $i<$user_count; $i++)
                {
                    $name = $self->{cache}->get_xpath (
                                FILENAME => $self->{configfile},
                                XPATH    => [ 'access_control/login/passwd/user', 'name' ],
                                COUNTER  => [ $i, 0 ]);
                    $self->debug ("        scanned user ... ".$name);
                    next if ($name ne $self->{ident}->{name});
                    $self->debug ("        scanned user matchs searched user");
                    $user = $i;
                    last;
                }

                if (not defined $user or
                    ($name ne $self->{ident}->{name}))
                {
                    $self->setError (6273120, "Login failed.");
                    return undef;
                }

                $digest = $self->{cache}->get_xpath (
                            FILENAME => $self->{configfile},
                            XPATH    => [ 'access_control/login/passwd/user', 'digest' ],
                            COUNTER  => [ $user, 0 ]);
                $algorithm = $self->{cache}->get_xpath (
                            FILENAME => $self->{configfile},
                            XPATH    => [ 'access_control/login/passwd/user', 'algorithm' ],
                            COUNTER  => [ $user, 0 ]);

                ## create comparable value
                $self->{ident}->{algorithm} = lc ($algorithm);
                if ($self->{ident}->{algorithm} =~ /^sha1$/i)
                {
                    use Digest::SHA1;
                    my $digest = Digest::SHA1->new;
                    $digest->add($self->{cgi}->param ('passwd'));
                    $self->{ident}->{digest} = $digest->b64digest;
                } elsif ($self->{ident}->{algorithm} =~ /^md5$/i) {
                    use Digest::MD5;
                    my $digest = Digest::MD5->new;
                    $digest->add($self->{cgi}->param ('passwd'));
                    $self->{ident}->{digest} = $digest->b64digest;
                } elsif ($self->{ident}->{algorithm} =~ /^crypt$/i) {
                    $self->{ident}->{digest} = crypt ($self->{cgi}->param ('passwd'),
                                                      $digest);
                } else {
                    $self->setError (6273130, "An unknown algorithm was specified ".
                                            "for the passphrasehashing in the configuration!");
                    return undef;
                }

                $self->debug ("        ident name ... ".$self->{ident}->{name});
                $self->debug ("        ident algorithm ... ".$self->{ident}->{algorithm});
                $self->debug ("        ident digest ... ".$self->{ident}->{digest});
                $self->{journal}->{login}->{name} = $self->{ident}->{name};

                ## compare passphrases
                if ($self->{ident}->{digest} ne $digest) {
                    $self->setError (6273166, "Login failed.");
                    return undef;
                }

            } else {
                $self->setError (6273180, "An unknown database type was specified in the configuration!");
                return undef;
            }
        } else {

            my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

	    # Frame Managing Hack
            if( $self->{cgi}->param('redir') eq "" ) {
                # Let's see if this hack brings the login screen
                # on the principal frame - it is an hell of a hack!
		# I hope it work with most browsers!
                my $target = $self->{cgi}->url(-full=>0, -relative=>1);
                $target .= "?redir=1";
                print "Content-type: text/html\n\n";
                print $self->{cgi}->start_html( -onLoad=>"top.location.href='$target'" ) . $self->{cgi}->end_html() . "\n\n";
                exit 0;
            }
                                                                                
            $hidden_list->{"cmd"}  = "getStaticPage";
            $hidden_list->{"name"} = "index";

            $cmd_panel->[0] = '<input type="submit" name="submit" value="'.
                              $self->{gettext}('OK').'">';
            $cmd_panel->[1] = '<input type="reset" name="submit" value="'.
                              $self->{gettext}('Reset').'">';

            $info_list->{BODY}->[0]->[0] = $self->{gettext}('Login');
            $info_list->{BODY}->[0]->[1] = '<input type="text" name="login" value=""';
            $info_list->{BODY}->[1]->[0] = $self->{gettext}('Password');
            $info_list->{BODY}->[1]->[1] = '<input type="password" name="passwd" value=""';

            print "Content-Type: text/html\n\n";
            $self->{output_func} (
                                  "NAME" => $self->{gettext}('Login to OpenCA'),
                                  "HIDDEN_LIST" => $hidden_list,
                                  "INFO_LIST"   => $info_list,
                                  "CMD_PANEL"   => $cmd_panel,
				  "TARGET"	=> "_top"
                                 );
            exit (0);
        }
    } elsif ($self->{ident}->{type} =~ /^x509$/i) {
        $self->debug ("        type ... x509");
        $self->{journal}->{login}->{type} = "x509";

        use OpenCA::OpenSSL;
        use OpenCA::PKCS7;

        if ($self->{cgi}->param ('signature')) {
            $self->debug ("        signature ... present");

            ## identification finished
            $self->{session}->param ('prepare_ident', '');

            ## starting verification of the signature

            my $challenge = $self->{cgi}->param( 'text' );
            my $signature = $self->{cgi}->param( 'signature' );

            $signature =~ s/\n*$//;

            my $h;
            if ($signature !~ /^\s*$/) {
                $h .= "-----BEGIN PKCS7-----\n";
                $h .= "$signature\n";
                $h .= "-----END PKCS7-----\n";
                $signature = $h;
            }

            ## Build a new PKCS7 object
            my $sig = new OpenCA::PKCS7( SHELL     => $self->{cryptoShell},
                                         SIGNATURE => $signature,
                                         DATA      => $challenge,
                                         CA_DIR    => $self->{cache}->get_xpath (
                                                          FILENAME => $self->{configfile},
                                                          XPATH    => 'access_control/login/chain'
                                                                                ));

            if (not $sig) {
                $self->{session}->stop();
                $self->setError (6273250, "Cannot build PKCS#7-object from extracted signature!\n".
                                          "OpenCA::PKCS7 returns errorcode ".
                                          $OpenCA::PKCS7::errno.
                                          " (".$OpenCA::PKCS7::errval.")");
                return undef;
            }

            if( $sig->status() != 0 ) {
                $self->{session}->stop();
                $self->setError (6273260, "The PKCS#7-object signals an error. The signature is not valid.\n".
                                          "PKCS#7-Error ".$OpenCA::PKCS7::errno.": ".$OpenCA::PKCS7::errval);
                return undef;
            }

            ## now the signature is correctly verified with the CA's own certchain
            ## the certificate's serial is uniqe in PKI
            $self->{ident}->{name} = $sig->getSigner()->{SERIAL};
            $self->{journal}->{login}->{name} = $self->{ident}->{name};

        } else {

            ## start a new session
            $self->{session}->start();
            $self->{session}->setParam ('name', '');
            $self->{session}->setParam ('valid', '1');
            $self->{session}->setParam ('prepare_ident', '1');
            $self->{journal}->{login}->{prepare_ident} = "TRUE";

            my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

            $hidden_list->{"cmd"}       = "getStaticPage";
            $hidden_list->{"name"}      = "index";
            $hidden_list->{"signature"} = "";
            $hidden_list->{"text"}      = $self->{session}->getID();

            $cmd_panel->[0] = '<input TYPE="Button" Name="Submit" Value="'.
                              $self->{gettext}('Sign and Login').
                              '" onClick="signForm( this.form, window)">';

            $info_list->{BODY}->[0]->[0] = $self->{gettext}('Challenge');
            $info_list->{BODY}->[0]->[1] = $self->{session}->getID();

            print "Content-Type: text/html\n\n";
            $self->{output_func} (
                                  "NAME"        => $self->{gettext}('Login to OpenCA'),
                                  "EXPLANATION" => $self->{gettext}('Please sign the challenge'),
                                  "SIGN_FORM"   => 1,
                                  "HIDDEN_LIST" => $hidden_list,
                                  "INFO_LIST"   => $info_list,
                                  "CMD_PANEL"   => $cmd_panel
                                 );
            exit (0);
        }
    } else {
        $self->setError (6273966, "An unknown login type was specified in the configuration!");
        return undef;
    }
    $self->debug ("    Logged in ...");
    return 1;
}

sub stopSession {
    my $self = shift;
    $self->debug ("    Remove session ...");

    $self->{CRYPTO}->stopSession;

    $self->{journal}->{session_id}   = $self->{session}->getID();
    $self->{journal}->{session_type} = "cookie";

    $self->{session}->stop();
    $self->{journal}->{message} .= "Session killed (normal logout).\n";

    $self->checkAccess;

    return 1;
}

##################################################################
##                 control the access rights                    ##
##################################################################

## we know the following files:
##
##     roles.xml
##     operations.xml
##     acl.xml
##     modules.xml
##     every cmds has it's own configfile
##
## we can support the following twig-handles
##
##     twig_roles      (useless for ACL checking)
##     twig_acl
##     twig_modules    (useless for ACL checking)
##     twig_operations (useless for ACL checking)
##     twig_cmd

sub checkACL {

    my $self = shift;
    $self->debug ("    checkACL ...");

    ## check ACL for activation
    $self->{acl}->{mode} = "on";
    if (not $self->{cache}->get_xpath (
                FILENAME => $self->{configfile},
                XPATH    => 'access_control/acl_config/acl')) {
        $self->setError (6290005, "The xml path to the access control is missing (access_control/acl_config/acl).");
        return undef;
    } elsif ( $self->{cache}->get_xpath (
                  FILENAME => $self->{configfile},
                  XPATH    => 'access_control/acl_config/acl') =~ /^no$/i) {
        $self->{journal}->{acl}->{mode} = "off";
        return 1;
    } elsif ( $self->{cache}->get_xpath (
                  FILENAME => $self->{configfile},
                  XPATH    => 'access_control/acl_config/acl') !~ /^yes$/i) {
        $self->setError (6290010, "The mode of the access control list (ACL) cannot be determined.");
        return undef;
    } ## else is an activated ACL
    $self->{journal}->{acl} = $self->{acl};
    $self->debug ("    ACL found");

    ## load xml files
    return undef if (not $self->getConfigsRBAC());
    $self->debug ("    RBAC loaded");

    ## get module
    return undef if (not $self->getModule());
    $self->debug ("    module loaded");

    ## get role
    return undef if (not $self->getRole());
    $self->debug ("    role loaded");

    ## get operation
    return undef if (not $self->getOperation());
    $self->debug ("    operation loaded");

    ## getOwner
    return undef if (not $self->getOwner());
    $self->debug ("    owner loaded");

    ## search a positive entry
    return undef if (not $self->getAccess());
    $self->debug ("    access granted");

    return 1;
}

sub getConfigsRBAC {

    my $self = shift;

    $self->{acl_file}  = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => 'access_control/acl_config/list');
    if (not $self->{acl_file}) {
        $self->setError (6291005, "The xml path to the access control is missing (access_control/acl_config/list).");
        return undef;
    }

    my $twig_cmds = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => 'access_control/acl_config/command_dir');
    if (not $twig_cmds) {
        $self->setError (6291025, "The xml path to the access control is missing (access_control/acl_config/command_dir).");
        return undef;
    }
    my $cmd = $self->{cgi}->param ('cmd');
    $self->{cmdfile} = $twig_cmds."/".$cmd.".xml";
    my $cmp_cmd = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/name');
    if (not $cmp_cmd) {
        $self->setError (6291050, "The xml path to the access control is missing (command_config/command/name).");
        return undef;
    }
    if ($cmp_cmd ne $cmd) {
        $self->setError (6291060,
                         "The filename of the command configuration don't match the included command configuration (".
                         $cmp_cmd."/$cmd).");
        return undef;
    }

    return 1;
}

sub getModule {

    my $self = shift;
    $self->{acl}->{module_id} = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/module_id');
    if (not defined $self->{acl}->{module_id}) {
        $self->setError (6292010, "The xml path to the access control is missing (access_control/acl_config/module_id).");
        return undef;
    }

    if ($self->{acl}->{module_id} != 0 and ( not $self->{acl}->{module_id} or $self->{acl}->{module_id} < 0)) {
        return undef;
    }

    return 1;
}

sub getRole {

    my $self = shift;

    $self->{ca_cert} = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/ca_cert');

    ## should we map the user to a role?
    my $map_role = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/map_role');
    if (not $map_role) {
        $self->setError (6293005, "The xml path to the access control is missing (access_control/acl_config/map_role).");
        return undef;
    }
    if ($map_role =~ /^no$/i) {
        $self->{acl}->{role} = $self->{ident}->{name};
        return 1;
    } elsif ($map_role !~ /^yes$/i) {
        $self->setError (6293010, "There is a problem with the configuration. ".
                                  "Should the user be mapped to a role?");
        return undef;
    } ## else --> we map the user to a role

    ## can we map the user to a role?
    ## we need the serial of a cert to do this
    ## this requires that ident performs a x509 identification
    if ($self->{ident}->{type} !~ /^x509$/i) {
        $self->setError (6293010, "There is a problem with the configuration. ".
                                  "A user can only be mapped to a role if the identification ".
                                  "uses certificates.");
        return undef;
    }

    ## load the certificate
    my $cert = $self->{db}->getItem (KEY => $self->{ident}->{name}, DATATYPE => "VALID_CERTIFICATE");
    if (not $cert) {
        $self->setError (6293020, "Cannot load certificate ".$self->{ident}->{name}." from the database.");
        return undef;
    }

    ## does this make sense?
    ## check signature of role
    if (not $self->{cryptoShell}->verify (
                DATA      => $cert->getSerial()."\n".$cert->getParsed()->{HEADER}->{ROLE},
                SIGNATURE => $cert->getParsed()->{HEADER}->{ROLE_SIGNATURE},
                CA_CERT   => $self->{ca_cert},
                NOCHAIN   => "1" ) and
        $self->{cryptoShell}->{errno})
    {
        $self->setError (6293030, "Invalid signature of the role of the user ".
                                  $self->{ident}->{name}." (Hackers on the Road?)!");
        return undef;
    }

    ## get role
    $self->{acl}->{role} = $cert->getParsed()->{HEADER}->{ROLE};

    return 1;
}

sub getOperation {

    my $self = shift;

    $self->{acl}->{cmd} = $self->{cgi}->param ('cmd');

    ## should we map the command to an operation
    my $map_operation = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/map_operation');
    if (not $map_operation) {
        $self->setError (6294005, "The xml path to the access control is missing (access_control/acl_config/map_operation).");
        return undef;
    }
    if ($map_operation =~ /^no$/i) {
        $self->{acl}->{operation} = $self->{acl}->{cmd};
        return 1;
    } elsif ($map_operation !~ /^yes$/i) {
        $self->setError (6294010, "There is a problem with the configuration. ".
                                  "Should the command be mapped to an operation?");
        return undef;
    } ## else --> we map the command to an operation

    ## get the operation from the commands configuration
    $self->{acl}->{operation} = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/operation');

    ## check that we have the correct file
    ## already done after initial loading of the file

    return 1;
}

sub getOwner {

    my $self = shift;

    ## check the configuration
    $self->{acl}->{owner_method} = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/owner_method');
    $self->{acl}->{owner_argument} = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/owner_argument');
    if (not defined $self->{acl}->{owner_method}) {
        $self->setError (6295010, "The xml path to the access control is missing (command_config/command/owner_method).");
        return undef;
    }
    if (not defined $self->{acl}->{owner_argument}) {
        $self->setError (6295015, "The xml path to the access control is missing (command_config/command/owner_argument).");
        return undef;
    }

    ## if we sign our configfiles then we must verify them here

    ## what we have for owners ?
    ##
    ## Certification Authority (empty owner_method)
    ## CERTIFICATE_SERIAL
    ## CSR_SERIAL
    ## CRR_SERIAL
    ## CGI
    ## ANY

    ## check for certificates
    if ( not $self->{acl}->{owner_method}) {
        $self->{acl}->{object} = "";
        $self->{acl}->{owner}  = "";
    } elsif ( $self->{acl}->{owner_method} =~ /^CERTIFICATE_SERIAL$/i ) {
        ## load serial
        if ( $self->{cgi}->param ($self->{acl}->{owner_argument}) < 1 ) {
            ## CA_CERTIFICATE detected
            ## owner is CA 
            ## wrong --> method
            $self->{acl}->{object} = "";
            $self->{acl}->{owner}  = "";
        } else {
            $self->{acl}->{object} = $self->{cgi}->param ($self->{acl}->{owner_argument});
    
            ## load the certificate
            my @certs;
            if (length ($self->{acl}->{object}) < 16) {
                @certs = $self->{db}->searchItems (KEY => $self->{acl}->{object}, DATATYPE => "CERTIFICATE");
            } else {
                @certs = $self->{db}->searchItems (KEY => $self->{acl}->{object}, DATATYPE => "CA_CERTIFICATE");
            }
            my $cert;
            $cert = $certs[0] if (@certs);
            if (not $cert) {
                $self->setError (6295020, "Cannot load certificate ".$self->{acl}->{object}." from the database.");
                return undef;
            }

            ## does this make sense?
            ## check signature of role
            if (not $self->{cryptoShell}->verify (
                        DATA      => $cert->getSerial()."\n".$cert->getParsed()->{HEADER}->{ROLE},
                        SIGNATURE => $cert->getParsed()->{HEADER}->{ROLE_SIGNATURE},
                        CA_CERT   => $self->{ca_cert},
                        NOCHAIN   => "1" ) and
                $self->{cryptoShell}->{errno})
            {
                $self->setError (6295030, "Invalid signature of the role of the user ".
                                          $self->{acl}->{object}." (Hackers on the Road?)!");
                return undef;
            }

            $self->{acl}->{owner} = $cert->getParsed()->{HEADER}->{ROLE};
        }

    ## check for certificate signing requests
    } elsif ( $self->{acl}->{owner_method} =~ /^CSR_SERIAL$/i ) {
        $self->{acl}->{object} = $self->{cgi}->param ($self->{acl}->{owner_argument});
        my $req = $self->{db}->getItem ( DATATYPE => "REQUEST",
                                 KEY      => $self->{acl}->{object} );
        if (not $req) {
                $self->setError (6295030, "Cannot load CSR ".$self->{acl}->{object}." from the database.");
                return undef;
        }

        ## this is actually the only part of the RBAC where the
        ## role is not protected by a signature
        $self->{acl}->{owner} = $req->getParsed()->{HEADER}->{ROLE};

    ## check for CRRs
    } elsif ( $self->{acl}->{owner_method} =~ /^CRR_SERIAL$/i ) {
        $self->{acl}->{object} = $self->{cgi}->param ($self->{acl}->{owner_argument});
        my $req = $self->{db}->getItem ( DATATYPE => "CRR",
                                 KEY      => $self->{acl}->{object} );
        if (not $req) {
                $self->setError (6295040, "Cannot load CRR ".$self->{acl}->{object}." from the database.");
                return undef;
        }

        ## load the certificate
        my $cert = $self->{db}->getItem (KEY => $req->getParsed()->{REVOKE_CERTIFICATE_SERIAL},
                                 DATATYPE => "CERTIFICATE");
        if (not $cert) {
            $self->setError (6295050, "Cannot load certificate ".
                                      $req->getParsed()->{REVOKE_CERTIFICATE_SERIAL}.
                                      " from the database.");
            return undef;
        }

        ## does this make sense?
        ## check signature of role
        if (not $self->{cryptoShell}->verify (
                    DATA      => $cert->getSerial()."\n".$cert->getParsed()->{HEADER}->{ROLE},
                    SIGNATURE => $cert->getParsed()->{HEADER}->{ROLE_SIGNATURE},
                    CA_CERT   => $self->{ca_cert},
                    NOCHAIN   => "1" ) and
            $self->{cryptoShell}->{errno})
        {
            $self->setError (6295060, "Invalid signature of the role of the certificate ".
                                      $req->getParsed()->{REVOKE_CERTIFICATE_SERIAL}.
                                      " (Hackers on the Road?)!");
            return undef;
        }

        $self->{acl}->{owner} = $cert->getParsed()->{HEADER}->{ROLE};

    ## owner will be directly identified by the user
    ## FIXME: how can I trust the recommendation of a user during ACL evaluation?
    } elsif ( $self->{acl}->{owner_method} =~ /^CGI$/i ) {
        $self->{acl}->{owner} = $self->{cgi}->param ($self->{acl}->{owner_argument});

    ## ignore the owner
    } elsif ( $self->{acl}->{owner_method} =~ /^ANY$/i ) {
        ## "superuser"
        ## this is no problem because there are no regular objects which can
        ## be owned by the CA or a normal role
        $self->{acl}->{owner} = "";
    } else {
        $self->setError (6295090, "The used owner method ".
                                  $self->{acl}->{owner_method}.
                                  " is unknown so there is a misconfiguration of the command ".
                                  $self->{acl}->{cmd}.".");
        return undef;
    }

    return 1;
}

sub getAccess {

    my $self = shift;

    ## load the complete list
    my $all = $self->{cache}->get_xpath_count (
                   FILENAME => $self->{acl_file},
                   XPATH    => 'access_control/acl/permission');

    ## don't accept an empty list
    if (not $all) {
        $self->setError (6296010, "The access control list is empty.");
        return undef;
    }

    my $ok = 0;
    ## check each entry
    for (my $i=0; $i<$all; $i++) {
        my $module = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'module' ],
                         COUNTER  => [ $i, 0 ]);
        my $role = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'role' ],
                         COUNTER  => [ $i, 0 ]);
        my $operation = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'operation' ],
                         COUNTER  => [ $i, 0 ]);
        my $owner = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'owner' ],
                         COUNTER  => [ $i, 0 ]);
        next if (not defined $module);
        next if (not defined $role);
        next if (not defined $operation);
        next if (not defined $owner);
        next if ($self->{acl}->{module_id} !~ /${module}/);
        next if ($self->{acl}->{role}      !~ /${role}/);
        next if ($self->{acl}->{operation} !~ /${operation}/);
        next if ($self->{acl}->{owner}     !~ /${owner}/);
        $self->debug ("getAccess: access granted");
        $ok = 1;
        last;
    }
    if (not $ok) {
        $self->setError (6296060, "Permission denied.");
        return undef;
    }

    return 1;
}

#######################################################################
##                    remove old sessions                            ##
#######################################################################

sub cleanupSessions {

    my $self = shift;

    my $expired = 0;
    my $dir = $self->{cache}->get_xpath (
                  FILENAME => $self->{configfile},
                  XPATH    => 'access_control/session/directory');

    ## load all sessions
    opendir DIR, $dir;
    my @session_files = grep /^(?!\.\.$).*/, grep /^(?!\.$)./, readdir DIR;
    closedir DIR;

    return $expired if (not scalar @session_files);

    ## check every session
    foreach my $session_file (@session_files)
    {
        ## extract session_id
        $session_file =~ s/cgisess_//;

        ## load session
        my $session = new CGI::Session(
                             undef,
                             $session_file,
                             {Directory=>$dir});

        ## check expiration
        $self->{journal}->{session_cleanup}->{$session_file} = "ok";
        if (not $session->param ('valid')) {
            ## delete session if not valid
            $session->delete;
            $expired++;
            $self->{journal}->{session_cleanup}->{$session_file} = "deleted";
        }
    }

    ## return the number of expired sessions
    return $expired;
}

#######################################################################
##                    load data for tokens                           ##
#######################################################################

sub initToken {
    my $self = shift;

    $self->debug ("initToken: starting");

    $self->getTokenParam ($self->{session}->getParam ('ACCESS_CONTROL_TOKEN_NAME'))
        if ($self->{session}->getParam ('ACCESS_CONTROL_TOKEN_LOGIN'));

    $self->debug ("initToken: successfully finished");

    return 1;
}

sub getTokenParam {

    my $self = shift;
    $self->debug ("    OpenCA::AC->getTokenParam ...");

    ## check the name of the token
    my $name;
    if (scalar @_)
    {
        $name = shift;
    } else {
        $name = $self->{session}->getParam ('ACCESS_CONTROL_TOKEN_NAME');
    }
    $self->{journal}->{token}->{name} = $name;
    $self->debug ("    OpenCA::AC->getTokenParam: name=".$name);

    ## get the number of arguments
    my $argc;
    if (scalar @_)
    {
        $argc = shift;
    } else {
        $argc = $self->{session}->getParam ('ACCESS_CONTROL_TOKEN_LOGIN');
    }
    $self->{journal}->{token}->{param_counter} = $argc;
    $self->debug ("    OpenCA::AC->getTokenParam: argc=".$argc);

    ## are the arguments present?
    my $argv = "";
    for (my $i=0; $i<$argc; $i++)
    {
        $argv .= $self->{cgi}->param ($name.'_GET_TOKEN_PARAM_'.$i);
    }
    $self->debug ("    OpenCA::AC->getTokenParam: argv=".$argv);
    if ($argv)
    {
        ## restore the CGI data if initial request
        $self->debug ("    OpenCA::AC->getTokenParam: restore CGI data");
        if ($self->{session}->getParam ('ACCESS_CONTROL_TOKEN_LOGIN'))
        {
            $self->{session}->loadParams();
            $self->{session}->setParam ('ACCESS_CONTROL_TOKEN_LOGIN', '0');
            $self->{session}->clear();
            $self->{session}->setParam('name', $self->{ident}->{name});
            $self->{session}->setParam('valid', '1');
        }

        ## build the returned array
        my @res = undef;
        for (my $i=0; $i<$argc; $i++)
        {
            push @res, $self->{cgi}->param ($name.'_GET_TOKEN_PARAM_'.$i);
        }
        $self->{journal}->{token}->{result} = "returned params";
        return @res;
    } else {
        $self->debug ("    OpenCA::AC->getTokenParam: ask for passphrase(s)");

        ## prepare session
        $self->{session}->saveParams ();
        $self->{session}->setParam ('ACCESS_CONTROL_TOKEN_NAME',  $name);
        $self->{session}->setParam ('ACCESS_CONTROL_TOKEN_LOGIN', $argc);

        ## ask for passphrase
        $self->getTokenConfig;
        my $tokens = $self->{cache}->get_xpath_count (
                         FILENAME => $self->{tokenfile},
                         XPATH    => 'token_config/token');
        for (my $i=0; $i<$tokens; $i++)
        {
            my $token_name = $self->{cache}->get_xpath (
                         FILENAME => $self->{tokenfile},
                         XPATH    => [ 'token_config/token', 'name' ],
                         COUNTER  => [ $i, 0 ]);
            next if ($token_name ne $name);

            my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

            $hidden_list->{"cmd"}  = "getStaticPage";
            $hidden_list->{"name"} = "index";

            $cmd_panel->[0] = '<input type="submit" name="submit" value="'.
                              $self->{gettext}('OK').'">';
            $cmd_panel->[1] = '<input type="reset" name="submit" value="'.
                              $self->{gettext}('Reset').'">';

            my $rows;
            for (my $i=0; $i<$argc; $i++)
            {
                if ($_[$i])
                {
                    $info_list->{BODY}->[$i]->[0] = $self->{gettext}($_[$i]);
                    $info_list->{BODY}->[$i]->[1] = '<input type="password" name="'.
                                                    "${name}_GET_TOKEN_PARAM_${i}".
                                                    '" value=""';
                } else {
                    $info_list->{BODY}->[$i]->[0] = $self->{gettext}('Password');
                    $info_list->{BODY}->[$i]->[0] .= " $i" if ($argc > 1);
                    $info_list->{BODY}->[$i]->[1] = '<input type="password" name="'.
                                                    "${name}_GET_TOKEN_PARAM_${i}".
                                                    '" value=""';
                }
            }

            if ($self->{cgi}->param('cmd') =~
                /(bpRecoverCert|send_cert_key|send_cert_key_openssl|send_cert_key_pkcs12|send_cert_key_pkcs8|getcert|sendcert|send_email_cert)/ ) {
                print "Content-type: text/html\n\n";
            }
            $self->{output_func} (
                                  "NAME"        => $self->{gettext}('Token Login'),
                                  "EXPLANATION" => $self->{gettext}('Please enter your credentials.'),
                                  "HIDDEN_LIST" => $hidden_list,
                                  "INFO_LIST"   => $info_list,
                                  "CMD_PANEL"   => $cmd_panel
                                 );
            $self->{journal}->{token}->{result} = "printed login page";
            exit (0);
        }
        $self->setError (6245080, "The requested token is not configured ($name).");
        return undef;
    }
}

sub getTokenConfig {
    my $self = shift;

    ## check for token_config
    my $token_config_ref = $self->{cache}->get_xpath (
                           FILENAME => $self->{configfile},
                           XPATH    => 'token_config_file');
    return $self->setError (6247010, "The xml path to the token configuration is missing (token_config).")
        if (not defined $token_config_ref);

    ## is token_config a reference?
    if ($token_config_ref)
    {
        $self->{tokenfile} = $token_config_ref;
    } else {
        $self->{tokenfile} = $self->{configfile};
    }

    return 1;
}

1;
