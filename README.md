Firewall Kernel Module
======================

This source code is from my post in zaghaghi.blog.ir.

Build
-----
    $ make

Insert Module
-------------
    $ sudo insmod firewall1.ko
or

    $ sudo insmod firewall2.ko

View Log File
-------------
    $ tailf /var/log/kern.log

Remove Module
-------------
    $ sudo rmmod firewall1.ko
or

    $ sudo rmmod firewall2.ko



