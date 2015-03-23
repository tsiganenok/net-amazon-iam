package Net::Amazon::IAM;
use Moose;

use URI;
use Carp;
use JSON;
use URI::Encode;
use XML::Simple;
use POSIX qw(strftime);
use LWP::UserAgent;
use LWP::Protocol::https;
use Data::Dumper qw(Dumper);
use Params::Validate qw(validate SCALAR ARRAYREF HASHREF);
use HTTP::Request::Common;
use AWS::Signature4;

use Net::Amazon::IAM::Error;
use Net::Amazon::IAM::Errors;
use Net::Amazon::IAM::User;
use Net::Amazon::IAM::Policy;
use Net::Amazon::IAM::Policies;
use Net::Amazon::IAM::UserPolicy;
use Net::Amazon::IAM::Group;
use Net::Amazon::IAM::AccessKey;
use Net::Amazon::IAM::AccessKeyMetadata;
use Net::Amazon::IAM::AccessKeysList;

our $VERSION = '0.03';

=head1 NAME

Net::Amazon::IAM - Perl interface to the Amazon Identity and Access Management.

=head1 VERSION

This is Net::Amazon::IAM version 0.03

IAM Query API version: '2010-05-08'

=head1 SYNOPSIS

 use Net::Amazon::IAM;

 my $iam = Net::Amazon::IAM->new(
   AWSAccessKeyId  => 'PUBLIC_KEY_HERE',
   SecretAccessKey => 'SECRET_KEY_HERE'
 );

 # create new user
 my $user = $iam->create_user (
   UserName => 'testuser',
   Path     => '/path/to/test/user/',
 );

 # delete user
 my $delete = $iam->delete_user(UserName => 'testuser');
 if($delete->isa("Net::Amazon::IAM::Error")) {
   print Dumper $delete;
 }else{
   print "User was successfuly deleted\n";
 }

 # prepare user policy document
 my $policy_document = {
   Version => '2012-10-17',
   Statement => [
      {
         Effect   => 'Allow',
         Action   => [
            's3:Get*',
            's3:List*',
         ],
         Resource => [
            'arn:aws:s3:::sometestbucket',
            'arn:aws:s3:::sometestbucket/*',
         ],
      },
   ],
 };

 # attach the document to the user
 my $policy = $iam->put_user_policy (
    PolicyName     => 'somtestpolicy',
    UserName       => 'sometestuser',
    PolicyDocument => $policy_document,
 );

 if($policy->isa("Net::Amazon::IAM::Error")) {
   print Dumper $policy;
 }else{
   print "Policy was added\n";
 }


If an error occurs while communicating with IAM, these methods will
throw a L<Net::Amazon::IAM::Error> exception.

=head1 DESCRIPTION

This module is a Perl interface to Amazon's Identity and Access Management (IAM). It uses the Query API to
communicate with Amazon's Web Services framework.

=head1 CLASS METHODS

=head2 new(%params)

This is the constructor, it will return you a Net::Amazon::IAM object to work with.  It takes
these parameters:

=over

=item AWSAccessKeyId (required)

Your AWS access key.

=item SecretAccessKey (required)

Your secret key, B<WARNING!> don't give this out or someone will be able to use your account
and incur charges on your behalf.

=item debug (optional)

A flag to turn on debugging. Among other useful things, it will make the failing api calls print
a stack trace. It is turned off by default.

=back

=cut

has 'AWSAccessKeyId' => (
   is       => 'ro',
   isa      => 'Str',
   lazy     => 1,
   default  => sub {
      if (defined($_[0]->temp_creds)) {
         return $_[0]->temp_creds->{'AccessKeyId'};
      } else {
         return undef;
      }
   }
);

has 'SecretAccessKey' => (
   is       => 'ro',
   isa      => 'Str',
   lazy     => 1,
   default  => sub {
      if (defined($_[0]->temp_creds)) {
         return $_[0]->temp_creds->{'SecretAccessKey'};
      } else {
         return undef;
      }
   }
);

has 'SecurityToken' => (
   is        => 'ro',
   isa       => 'Str',
   lazy      => 1,
   predicate => 'has_SecurityToken',
   default   => sub {
      if (defined($_[0]->temp_creds)) {
         return $_[0]->temp_creds->{'Token'};
      } else {
         return undef;
      }
   }
);

has 'base_url' => (
   is          => 'ro',
   isa         => 'Str',
   lazy        => 1,
   default     => sub {
      return 'http' . ($_[0]->ssl ? 's' : '') . '://iam.amazonaws.com';
   }
);

has 'temp_creds' => (
   is        => 'ro',
   lazy      => 1,
   predicate => 'has_temp_creds',
   default   => sub {
      my $ret;
      $ret = $_[0]->_fetch_iam_security_credentials();
   },
);

has 'debug'             => ( is => 'ro', isa => 'Str',  default => 0 );
has 'version'           => ( is => 'ro', isa => 'Str',  default => '2010-05-08' );
has 'ssl'               => ( is => 'ro', isa => 'Bool', default => 1 );
has 'return_errors'     => ( is => 'ro', isa => 'Bool', default => 1 );

sub _timestamp {
   return strftime("%Y-%m-%dT%H:%M:%SZ",gmtime);
}

sub _fetch_iam_security_credentials {
   my $self = shift;
   my $retval = {};

   my $ua = LWP::UserAgent->new();
   # Fail quickly if this is not running on an EC2 instance
   $ua->timeout(2);

   my $url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

   $self->_debug("Attempting to fetch instance credentials");

   my $res = $ua->get($url);
   if ($res->code == 200) {
      # Assumes the first profile is the only profile
      my $profile = (split /\n/, $res->content())[0];

      $res = $ua->get($url . $profile);

      if ($res->code == 200) {
         $retval->{'Profile'} = $profile;
         foreach (split /\n/, $res->content()) {
            return undef if /Code/ && !/Success/;
            if (m/.*"([^"]+)"\s+:\s+"([^"]+)",/) {
               $retval->{$1} = $2;
            }
         }

         return $retval if (keys %{$retval});
      }
   }

   return undef;
}

sub _sign {
   my $self      = shift;
   my %args      = @_;
   my $action    = delete $args{'Action'};
   my %sign_hash = %args;
   my $timestamp = $self->_timestamp;

   $sign_hash{'Action'}           = $action;
   $sign_hash{'Version'}          = $self->version;

   if ($self->has_temp_creds || $self->has_SecurityToken) {
      $sign_hash{'SecurityToken'} = $self->SecurityToken;
   }

   my $signer = AWS::Signature4->new(
      -access_key => $self->{'AWSAccessKeyId'},
      -secret_key => $self->{'SecretAccessKey'},
   );

   my $ua = LWP::UserAgent->new();

   my $request = POST(
      $self->base_url,
      [
         %sign_hash,
      ],
   );

   $signer->sign($request);

   my $res = $ua->request($request);

   # We should force <item> elements to be in an array
   my $xs   = XML::Simple->new(
      ForceArray => qr/(?:item|Errors)/i, # Always want item elements unpacked to arrays
      KeyAttr => '',                      # Turn off folding for 'id', 'name', 'key' elements
      SuppressEmpty => undef,             # Turn empty values into explicit undefs
   );
   my $xml;

   # Check the result for connectivity problems, if so throw an error
   if ($res->code >= 500) {
      my $message = $res->status_line;
      $xml = <<EOXML;
<xml>
   <RequestID>N/A</RequestID>
   <Errors>
      <Error>
         <Code>HTTP POST FAILURE</Code>
         <Message>$message</Message>
      </Error>
   </Errors>
</xml>
EOXML

   } else {
      $xml = $res->content();
   }

   my $ref = $xs->XMLin($xml);
   warn Dumper($ref) . "\n\n" if $self->debug == 1;

   return $ref;
}

sub _parse_errors {
   my $self       = shift;
   my $errors_xml = shift;

   my $es;
   my $request_id = $errors_xml->{'RequestId'};

   my $error = Net::Amazon::IAM::Error->new(
      code       => $errors_xml->{'Error'}{'Code'},
      message    => $errors_xml->{'Error'}{'Message'},
      request_id => $request_id,
   );

   # Print a stack trace if debugging is enabled
   if ($self->debug) {
      confess 'Last error was: ' . $error;
   }

   return $error;
}

sub _debug {
   my $self    = shift;
   my $message = shift;

   if ((grep { defined && length} $self->debug) && $self->debug == 1) {
      print "$message\n\n\n\n";
   }
}

sub _build_filters {
   my ($self, $args) = @_;

   my $filters = delete $args->{Filter};

   return unless $filters && ref($filters) eq 'ARRAY';

   $filters = [ $filters ] unless ref($filters->[0]) eq 'ARRAY';
   my $count   = 1;
   foreach my $filter (@{$filters}) {
      my ($name, @args) = @$filter;
      $args->{"Filter." . $count.".Name"}      = $name;
      $args->{"Filter." . $count.".Value.".$_} = $args[$_-1] for 1..scalar @args;
      $count++;
   }
}

=head2 create_user(%params)

Create new IAM user

=over

=item UserName (required)

New user username

=item Path (optional)

Where to create new user

=back

Returns a Net::Amazon::IAM::User object on success or Net::Amazon::IAM::Error on fail.

=cut

sub create_user {
   my $self = shift;

   my %args = validate(@_, {
      UserName => { type => SCALAR },
      Path     => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action  => 'CreateUser', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return Net::Amazon::IAM::User->new(
         $xml->{'CreateUserResult'}{'User'},
      );
   }
}

=head2 delete_user(%params)

Delete IAM User

=over

=item UserName (required)

What user should be deleted

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub delete_user {
   my $self = shift;

   my %args = validate(@_, {
      UserName => { type => SCALAR },
   });

   my $xml = $self->_sign(Action  => 'DeleteUser', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 get_user(%params)

Get IAM user details

=over

=item UserName (required)

New user username

=back

Returns a Net::Amazon::IAM::User object on success or Net::Amazon::IAM::Error on fail.

=cut

sub get_user {
   my $self = shift;

   my %args = validate(@_, {
      UserName => { type => SCALAR },
   });

   my $xml = $self->_sign(Action  => 'GetUser', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return Net::Amazon::IAM::User->new(
         $xml->{'GetUserResult'}{'User'},
      );
   }
}

=head2 update_user(%params)

Updates the name and/or the path of the specified user.

=over

=item UserName (required)

Name of the user to update. If you're changing the name of the user, this is the original user name.

=item NewPath (optional)

New path for the user. Include this parameter only if you're changing the user's path.

=item NewUserName (optional)

New name for the user. Include this parameter only if you're changing the user's name.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub update_user {
   my $self = shift;

   my %args = validate(@_, {
      UserName    => { type => SCALAR },
      NewPath     => { type => SCALAR, optional => 1 },
      NewUserName => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action  => 'UpdateUser', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 add_user_to_group(%params)

Adds the specified user to the specified group.

=over

=item GroupName (required)

The name of the group to update.

=item UserName (required)

The name of the user to add.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub add_user_to_group {
   my $self = shift;

   my %args = validate(@_, {
      GroupName => { type => SCALAR },
      UserName  => { type => SCALAR },
   });

   my $xml = $self->_sign(Action  => 'AddUserToGroup', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 remove_user_from_group(%params)

Removes the specified user from the specified group.

=over

=item GroupName (required)

The name of the group to update.

=item UserName (required)

The name of the user to remove.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub remove_user_from_group {
   my $self = shift;

   my %args = validate(@_, {
      GroupName => { type => SCALAR },
      UserName  => { type => SCALAR },
   });

   my $xml = $self->_sign(Action  => 'RemoveUserFromGroup', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 create_group(%params)

Creates a new group.

=over

=item GroupName (required)

The name of the group to create.

=item Path (optional)

The path to the group.

=back

Returns Net::Amazon::IAM::Group object on success or Net::Amazon::IAM::Error on fail.

=cut

sub create_group {
   my $self = shift;

   my %args = validate(@_, {
      GroupName => { type => SCALAR },
      Path      => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action  => 'CreateGroup', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return Net::Amazon::IAM::Group->new(
         $xml->{'CreateGroupResult'}{'User'},
      );
   }
}

=head2 get_group(%params)

Returns group details and list of users that are in the specified group.

=over

=item GroupName (required)

The name of the group.

=back

Returns Net::Amazon::IAM::Group object on success or Net::Amazon::IAM::Error on fail.
If there one or more users in specified group, Net::Amazon::IAM::Group object
will containt Users attribute wich is ArrayRef of Net::Amazon::IAM::User objects

=cut

sub get_group {
   my $self = shift;

   my %args = validate(@_, {
      GroupName => { type => SCALAR },
      Marker    => { type => SCALAR, optional => 1 },
      MaxItems  => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action  => 'GetGroup', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      my %result = %{$xml->{'GetGroupResult'}};

      my $users;
      for my $user ( @{$result{'Users'}{'member'}} ) {
         my $u = Net::Amazon::IAM::User->new(
            $user,
         );
         push @$users, $u;
      }

      return Net::Amazon::IAM::Group->new(
         IsTruncated => $result{'IsTruncated'},
         Users       => $users,
         %{$result{'Group'}},
      );
   }
}

=head2 delete_group(%params)

Deletes the specified group. The group must not contain any users or have any attached policies.

=over

=item GroupName (required)

The name of the group to delete.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub delete_group {
   my $self = shift;

   my %args = validate(@_, {
      GroupName => { type => SCALAR },
   });

   my $xml = $self->_sign(Action  => 'DeleteGroup', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 create_policy(%params)

Creates a new managed policy for your AWS account.

=over

=item PolicyName (required)

The name of the policy document.

=item PolicyDocument (required)

The policy document.

=item Description (optional)

A friendly description of the policy.

=item Path (optional)

The path for the policy.

=back

Returns Net::Amazon::IAM::Policy object on success or Net::Amazon::IAM::Error on fail.

=cut

sub create_policy {
   my $self = shift;

   my %args = validate(@_, {
      PolicyName     => { type => SCALAR },
      PolicyDocument => { type => HASHREF },
      Description    => { type => SCALAR, optional => 1 },
      Path           => { type => SCALAR, optional => 1 },
   });

   $args{'PolicyDocument'} = encode_json delete $args{'PolicyDocument'};

   my $xml = $self->_sign(Action  => 'CreatePolicy', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return Net::Amazon::IAM::Policy->new(
         $xml->{'CreatePolicyResult'}{'Policy'},
      );
   }
}

=head2 get_policy(%params)

Retrieves information about the specified managed policy.

=over

=item PolicyArn (required)

The Amazon Resource Name (ARN). ARNs are unique identifiers for AWS resources.

=back

Returns Net::Amazon::IAM::Policy object on success or Net::Amazon::IAM::Error on fail.

=cut

sub get_policy {
   my $self = shift;

   my %args = validate(@_, {
      PolicyArn => { type => SCALAR },
   });

   my $xml = $self->_sign(Action => 'GetPolicy', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return Net::Amazon::IAM::Policy->new(
         $xml->{'GetPolicyResult'}{'Policy'},
      );
   }
}

=head2 delete_policy(%params)

Deletes the specified managed policy.

=over

=item PolicyArn (required)

The Amazon Resource Name (ARN). ARNs are unique identifiers for AWS resources.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub delete_policy {
   my $self = shift;

   my %args = validate(@_, {
      PolicyArn => { type => SCALAR },
   });

   my $xml = $self->_sign(Action => 'DeletePolicy', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 list_policies(%params)

Lists all the managed policies that are available to your account, 
including your own customer managed policies and all AWS managed policies.

You can filter the list of policies that is returned using the optional 
OnlyAttached, Scope, and PathPrefix parameters. For example, to list only the 
customer managed policies in your AWS account, set Scope to Local. 
To list only AWS managed policies, set Scope to AWS.

=over

=item OnlyAttached (optional)

A flag to filter the results to only the attached policies.
When OnlyAttached is true, the returned list contains only the 
policies that are attached to a user, group, or role. 
When OnlyAttached is false, or when the parameter is not 
included, all policies are returned.

=item PathPrefix (optional)

The path prefix for filtering the results. 
If it is not included, it defaults to a slash (/), listing all policies.

=item Scope (optional)

The scope to use for filtering the results.

To list only AWS managed policies, set Scope to AWS. 
To list only the customer managed policies in your AWS account, set Scope to Local.
If it is not included, or if it is set to All, all policies are returned.

=back

Returns Net::Amazon::IAM::Policies on success or Net::Amazon::IAM::Error on fail.
When no policies found, the Policies attribute will be just empty array.

=cut

sub list_policies {
   my $self = shift;

   my %args = validate(@_, {
      Marker       => { type => SCALAR, optional => 1 },
      MaxItems     => { type => SCALAR, optional => 1 },
      PathPrefix   => { type => SCALAR, optional => 1, default => '/' },
      OnlyAttached => { regex => qr/true|false/, optional => 1, default => 'false' },
      Scope        => { regex => qr/AWS|Local|All/, optional => 1, default => 'All' },
   });

   my $xml = $self->_sign(Action => 'ListPolicies', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      my %result = %{$xml->{'ListPoliciesResult'}};
      my $policies;

      if ( grep { defined && length } $result{'Policies'} ) {
         if(ref($result{'Policies'}{'member'}) eq 'ARRAY') {
            for my $policy(@{$result{'Policies'}{'member'}}) {
               my $p = Net::Amazon::IAM::Policy->new(
                  $policy,
               );

               push @$policies, $p;
            }
         }else{
            my $p = Net::Amazon::IAM::Policy->new(
               $result{'Policies'}{'member'},
            );

            push @$policies, $p;
         }
      }else{
         $policies = [];
      }

      return Net::Amazon::IAM::Policies->new(
         Policies => $policies,
      );
   }
}

=head2 put_user_policy(%params)

Deletes the specified managed policy.

=over

=item PolicyDocument (required)

The policy document. Must be HashRef.

=item PolicyName (required)

The name of the policy document.

=item UserName (required)

The name of the user to associate the policy with.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub put_user_policy {
   my $self = shift;

   my %args = validate(@_, {
      PolicyDocument => { type => HASHREF },
      PolicyName     => { type => SCALAR },
      UserName       => { type => SCALAR },
   });

   $args{'PolicyDocument'} = encode_json delete $args{'PolicyDocument'};

   my $xml = $self->_sign(Action => 'PutUserPolicy', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 get_user_policy(%params)

Retrieves the specified inline policy document that is embedded in the specified user.

=over

=item PolicyName (required)

The name of the policy document to get.

=item UserName (required)

The name of the user who the policy is associated with.

=back

Returns Net::Amazon::IAM::UserPolicy object on success or Net::Amazon::IAM::Error on fail.

=cut

sub get_user_policy {
   my $self = shift;

   my %args = validate(@_, {
      PolicyName     => { type => SCALAR },
      UserName       => { type => SCALAR },
   });

   my $xml = $self->_sign(Action => 'GetUserPolicy', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      my $user_policy = Net::Amazon::IAM::UserPolicy->new(
         $xml->{'GetUserPolicyResult'}
      );
      $user_policy->{'PolicyDocument'} = decode_json(URI::Encode->new()->decode($user_policy->PolicyDocument));
      return $user_policy;
   }
}

=head2 delete_user_policy(%params)

Deletes the specified inline policy that is embedded in the specified user.

=over

=item PolicyName (required)

The name identifying the policy document to delete.

=item UserName (required)

The name (friendly name, not ARN) identifying the user that the policy is embedded in.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub delete_user_policy {
   my $self = shift;

   my %args = validate(@_, {
      PolicyName     => { type => SCALAR },
      UserName       => { type => SCALAR },
   });

   my $xml = $self->_sign(Action => 'DeleteUserPolicy', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 list_user_policies(%params)

Lists the names of the inline policies embedded in the specified user.

=over

=item UserName (required)

The name of the user to list policies for.

=back

When found one or more policies, this method will return ArrayRef with policy names.
Once no policies found, will return undef;
Net::Amazon::IAM::Error will be returned on error

=cut

sub list_user_policies {
   my $self = shift;

   my %args = validate(@_, {
      UserName => { type => SCALAR },
      Marker   => { type => SCALAR, optional => 1 },
      MaxItems => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action => 'ListUserPolicies', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      my $policies;

      my %result = %{$xml->{'ListUserPoliciesResult'}};

      if ( grep { defined && length } $result{'PolicyNames'} ) {
         if(ref($result{'PolicyNames'}{'member'}) eq 'ARRAY') {
            $policies = $result{'PolicyNames'}{'member'};
         }else{
            push @$policies, $result{'PolicyNames'}{'member'};
         }
      } else {
         $policies = undef;
      }

      return $policies;
   }
}

=head2 create_access_key(%params)

Creates a new AWS secret access key and corresponding AWS access key ID for the specified user.
The default status for new keys is Active.
If you do not specify a user name, IAM determines the user name implicitly based on the AWS access
key ID signing the request. Because this action works for access keys under the AWS account, you can use
this action to manage root credentials even if the AWS account has no associated users.

Important:
To ensure the security of your AWS account, the secret access key is accessible only during
key and user creation. You must save the key (for example, in a text file) if you want to be
able to access it again. If a secret key is lost, you can delete the access keys for the associated
user and then create new keys.

=over

=item UserName (optional)

The user name that the new key will belong to.

=back

Returns Net::Amazon::IAM::AccessKey object on success or Net::Amazon::IAM::Error on fail.

=cut

sub create_access_key {
   my $self = shift;

   my %args = validate(@_, {
      UserName => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action => 'CreateAccessKey', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return Net::Amazon::IAM::AccessKey->new(
         $xml->{'CreateAccessKeyResult'}{'AccessKey'},
      );
   }
}

=head2 delete_access_key(%params)

Deletes the access key associated with the specified user.

If you do not specify a user name, IAM determines the user name implicitly based
on the AWS access key ID signing the request. Because this action works for access
keys under the AWS account, you can use this action to manage root credentials even
if the AWS account has no associated users.

=over

=item AccessKeyId (required)

The access key ID for the access key ID and secret access key you want to delete.

=item UserName (optional)

The name of the user whose key you want to delete.

=back

Returns true on success or Net::Amazon::IAM::Error on fail.

=cut

sub delete_access_key {
   my $self = shift;

   my %args = validate(@_, {
      AccessKeyId => { type => SCALAR },
      UserName    => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action => 'DeleteAccessKey', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      return 1;
   }
}

=head2 list_access_keys(%params)

Returns information about the access key IDs associated with the specified user.
If the UserName field is not specified, the UserName is determined implicitly based on the AWS access
key ID used to sign the request. Because this action works for access keys under the AWS account,
you can use this action to manage root credentials even if the AWS account has no associated users.

=over

=item UserName (optional)

The name of the user.

=back

Returns Net::Amazon::IAM::AccessKeysList on success.
If specified user has no keys, "Keys" attribute of Net::Amazon::IAM::AccessKeysList object
will be just empty array.
Returns Net::Amazon::IAM::Error on fail.

=cut

sub list_access_keys {
   my $self = shift;

   my %args = validate(@_, {
      UserName => { type => SCALAR, optional => 1 },
   });

   my $xml = $self->_sign(Action => 'ListAccessKeys', %args);

   if ( grep { defined && length } $xml->{'Error'} ) {
      return $self->_parse_errors($xml);
   } else {
      my %result = %{$xml->{'ListAccessKeysResult'}};
      my $keys;

      if ( grep { defined && length } $result{'AccessKeyMetadata'} ) {

         if(ref($result{'AccessKeyMetadata'}{'member'}) eq 'ARRAY') {
            for my $key ( @{$result{'AccessKeyMetadata'}{'member'}} ) {
               my $k = Net::Amazon::IAM::AccessKeyMetadata->new(
                  $key,
               );
               push @$keys, $k;
            }
         }else{
            my $k = Net::Amazon::IAM::AccessKeyMetadata->new(
               $result{'AccessKeyMetadata'}{'member'},
            );
            push @$keys, $k;
         }
      }else{
         $keys = [];
      }

      return Net::Amazon::IAM::AccessKeysList->new(
         Keys => $keys,
      );
   }
}

no Moose;
1;

=head1 AUTHOR

Igor Tsigankov <tsiganenok@gmail.com>

=head1 COPYRIGHT

Copyright (c) 2015 Igor Tsigankov.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

__END__
