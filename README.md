# rust-namespace-example
This program is an ugly, C-like Rust translation of the C example at the bottom of `man 2 clone` with some extra additions to launch a namespaced bash process. The particularly tricky bit is to remember to set the uid/gid maps correctly after cloning the process (see `man user_namespaces`), otherwise stuff like chroot won't work. For more about namespaces, see Michael Kerrisk's [Namespaces in Operation](https://lwn.net/Articles/531114/) series. 

Usage of the program requires two arguments: a hostname and a chroot path.

There are many resources out there on establishing a chroot. If you're on debian/ubuntu distros try `sudo debootstrap stable <chroot_path>`.