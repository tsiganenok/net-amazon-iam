package Net::Amazon::IAM::AccessKey;
use Moose;
extends 'Net::Amazon::IAM::AccessKeyMetadata';

has 'SecretAccessKey' => (
   is       => 'ro',
   isa      => 'Str',
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
