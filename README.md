# ja3box

![](/pics/logo.png)

extra ja3 when sniffing or from a pcap.

## Example
> online mode

`sudo python ja3box.py -i en0`
![](/pics/online.png)

> offline mode

`sudo python ja3box.py -f test.pcap`
![](/pics/offline.png)

> output json

`sudo python ja3box.py -i en0 --json`
![](/pics/output-json.png)

> save json to file

`sudo python ja3box.py -i en0 -of test.json --json`
![](/pics/output-json-to-file.png)

### more
```
» sudo python ja3box.py -h
usage: ja3box.py [-h] [-i I] [-f F] [-of OF] [-bpf BPF] [--json] [--savepcap]
                 [-pf PF]

Version: 1.0; Running in Py3.x

optional arguments:
  -h, --help  show this help message and exit
  -i I        the interface you want to use
  -f F        local pcap filename(in the offline mode)
  -of OF      print result to? (default: stdout)
  -bpf BPF    yes, it is BPF
  --json      print result as json
  --savepcap  save the raw pcap
  -pf PF      eg. `-pf test`: save the raw pcap as test.pcap

```
