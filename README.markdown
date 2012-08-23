### THIS SOFTWARE IS STILL IN ALPHA, I MAKE NO GUARANTEES ABOUT ITS CORRECTNESS

Dependencies:

* General system programs
    * ksetpass                       : From kadmin-remctl project
    * kinit/kdestroy/ktutil          : From krb5-user
    * rm                             : Standard rm command
    * ifconfig                       : net-tools (on linux, not sure about elsewhere)

* Perl Modules
    * Authen::SASL
    * English
    * Expect
    * File::Copy
    * File::Temp
    * FindBin
    * Getopt::Long
    * Net::DNS
    * Net::Domain
    * Net::LDAP
    * Pod::Usage
    * String::MkPasswd

* Linux Specific:
    * lsmod

* Solaris Specific:
    * encrypt
    * svcs
    * svcadm

Acknowledgements:
    This would have been vastly more difficult without the tangential
    assistance of Nico Williams and Baban Kenkre, through their work on
    adjoin.sh.


vim: et ts=4 sw=4 tw=75
