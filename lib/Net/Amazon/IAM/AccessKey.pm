package Net::Amazon::IAM::AccessKey;
use Moose;

has 'AccessKeyId' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
);

has 'CreateDate' => (
   is       => 'ro',
   isa      => 'Str',
   required => 0,
);

has 'SecretAccessKey' => (
   is       => 'ro',
   isa      => 'Str',
   required => 0,
);

has 'Status' => (
   is       => 'ro',
   isa      => 'Str',
   required => 0,
);

has 'UserName' => (
   is       => 'ro',
   isa      => 'Str',
   required => 1,
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
