# tcxmirror

Multiple TCX programs can be attached to both the ingress and the egress.
However, it can be tricky to inspect the state of packets after each TCX
program runs. Normal packet capture programs such as Wireshark capture before
the first TCX program on ingress and after the last one on egress.

This program is intended to run before or after one or more TCX programs have
been attached to an interface. It can hook before or after any given program
and mirror all traffic to a different interface, where it can be captured with
Wireshark or tcpdump.

## Building

Run `make`. You will need a recent Linux kernel (tested with 7.3) and libbpf
(tested with 1.5.0).

## Running

Usage:
```
Usage: tcxmirror -i <first|last> -e <first|last> <attach if> <mirror if>
```

A mirroring eBPF program is attached to the `attach if` in both ingress and
egress direction.  All traffic is mirrored to the `mirror if`.

If neither `-i` nor `-e` is specified, the mirroring programs are attached as
the last program on ingress and the first program on egress.

Otherwise both `-i` and `-e` take as parameter an index specifying at which
position in the chain of TCX programs the ingress, respectively the egress
mirroring program should be attached. An index of zero would attach the program
as the first program. Alternatively, both options take the `first` and `last`
paramters which attach the mirroring program as the first, respectively last
TCX program.
