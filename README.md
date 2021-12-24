# ja3box

<img src="/pics/logo.png" width="500">

extract ja3(s) when sniffing or from a pcap (or pcapng ...).

about ja3(s): 
1. https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
2. https://xz.aliyun.com/t/3889

理论上支持 TLS/SSL 全版本提取（精力有限未全部测试，如有问题请提交 issue）

## Env

1. `pip install scapy`
2. `pip install colorama`
2. py3.x
3. `macos`/`linux`/`windows`
4. **run as root when in the online mode**

## Example
> online mode

`sudo python ja3box.py -i en0`

<img src="/pics/online.png" width="600">

> offline mode

`sudo python ja3box.py -f test.pcap`

<img src="/pics/offline.png" width="600">

> output in json format

`sudo python ja3box.py -i en0 --json`

<img src="/pics/output-json.png">

> saved json as file

`sudo python ja3box.py -i en0 -of test.json --json`

<img src="/pics/output-json-to-file.png" width="600">

### More
```
» sudo python ja3box.py -h
usage: ja3box.py [-h] [-i I] [-f F] [-of OF] [-bpf BPF] [--json] [--savepcap]
                 [-pf PF]

Version: 2.0; Running in Py3.x

optional arguments:
  -h, --help  show this help message and exit
  -i I        interface or list of interfaces (default: sniffing on all
              interfaces)
  -f F        local pcap filename (in the offline mode)
  -of OF      print result to? (default: stdout)
  -bpf BPF    yes, it is BPF
  --json      print result as json
  --savepcap  save the raw pcap
  -pf PF      eg. `-pf test`: save the raw pcap as test.pcap

```

## Others
<img src="https://clean-1252075454.cos.ap-nanjing.myqcloud.com/20200528120800990.png" width="500">

[![Stargazers over time](https://starchart.cc/Macr0phag3/ja3box.svg)](https://starchart.cc/Macr0phag3/ja3box)
