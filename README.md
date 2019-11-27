# sysrepo-tsn
Application to configure tsn function
# trouble shooting
1. Host key issue:
output:
```
nc ERROR: Remote host key changed, the connection will be terminated!
nc ERROR: Checking the host key failed.
cmd_connect: Connecting to the 10.193.20.4:830 as user "root" failed.
```
To solve this problem, we can list knownhosts with `knownhosts`, Then delet
related item. For this case, we use `knownhosts --del 19`

2. format of number
Now, sysrepo only support dec format for number.

3. get-config

```
get-config [--help] --source running|startup|candidate [--filter-subtree[=<file>] | --filter-xpath <XPath>] [--defaults report-all|report-all-tagged|trim|explicit] [--out <file>]
```

- Get all the configuration in running datastore
get-config --source running

- filter by xpath1:

get-config --source running --filter-xpath /ieee802-dot1q-bridge:bridges

- filter by xpath2:
```
get-config --source running --filter-xpath /ieee802-dot1q-bridge:bridges/bridge[name='switch']/component[name='swp0']/ieee802-dot1q-stream-filters-gates:stream-gates
```

- filter by subtree file

get-config --source running --filter-subtree=<subtree.filter>

For the case to get bridges module, the content of subtree.filter like following:
```
/ieee802-dot1q-bridge:bridges
```
3. Copy the configuration of running datastore to startup datastore
```
copy-config --target startup --source running
```

