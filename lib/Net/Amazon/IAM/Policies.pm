package Net::Amazon::IAM::Policies;
use Moose;

=head1 NAME

Net::Amazon::IAM::Policies

=head1 DESCRIPTION

A class representing a IAM Policies list.

=head1 ATTRIBUTES

=over

=item Policies (optional)
   
List of Net::Amazon::IAM::Policy objects.

=back

=cut

has 'Policies' => (
   is       => 'ro',
   isa      => 'Maybe[ArrayRef[Net::Amazon::IAM::Policy]]',
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
