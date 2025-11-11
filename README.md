# vibesy RIIR samba / quasi-tractor experiment

Earlier in the year I decided to give claude code an honest try and
see if it could write a substantial, nontrivial program with complex
structure and requirements. Or at least _rewrite_ one it had sitting
next to it as a model.

To keep the task well defined, I told it to rewrite samba. Not a
line-by-line clone but "something that can serve SMB to smbclient",
allowing it to read samba as a reference and run smbclient as a test
oracle, but instructing it to produce idiomatic rust code.

I ran it on super duper max $200/mo plan for 4 days, babysitting it
about as much as I might an intern or junior developer, and it did ..
a surprisingly good job! By the end it was able to accept incoming
connections from smbclient, browse filesystem directories, upload and
download files.

The code is clunky, inefficient, feature-sparse, full of weird
hard-coded numbers and badly organized, duplicated and stylistically
clashing swerves, and probably quite a lot of security holes, but
.. it actually does work. Ish. Far more than I'd have been able to
write in a few days. I could imagine someone taking this and polishing
it into a real samba. Which seems to me quite .. something. I don't
know what exactly. A different situation than we were in a few years
ago, it seems to me. A weird situation.

The results are presented here for your amusement, curiosity or
edification. I'm not trying to make any particular point, and
certainly not challenge the supremacy of the actual battle-tested
samba software. I also don't want to pretend I have any sort of answer
for what a work like this means in terms of copyright, so I'm just
going to license it as GPL 3 (like samba) and call it a derivative
work. If someone wants to argue the contrary I suggest doing your own
version of this experiment. You'll probably get different results!