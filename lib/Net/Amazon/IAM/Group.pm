package Net::Amazon::IAM::Group;
use Moose;

has 'Arn' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
);

has 'CreateDate' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
);

has 'GroupId' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
);

has 'GroupName' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
);

has 'Path' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
);

has 'IsTruncated' => (
   is       => 'ro',
   isa      => 'Str',
   required => 0,
);

has 'Users' => (
   is       => 'ro',
   isa      => 'Maybe[ArrayRef[Net::Amazon::IAM::User]]',
   required => 0,
);

__PACKAGE__->meta->make_immutable();

=head1 AUTHOR

Igor Tsigankov <tsiganenok@gmail.com>

=head1 COPYRIGHT

Copyright (c) 2015 Igor Tsigankov . This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

no Moose;
1;
