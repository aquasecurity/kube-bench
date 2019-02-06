# Kube bench adapted to Giant Swarm

Orignal [README](https://github.com/aquasecurity/kube-bench/blob/master/README.md)

## Steps to run it on GS

1. Run master job in the desired cluster (`default` namespace)

```bash
$ kubectl apply -f job_master.yaml
```

2. Check pod succedded and get results in CSV
```bash
$ kubectl get pod
$ kubectl logs -l job-name=kube-bench-master | jq -r '.tests[] | .results[] + {type: .desc} | [.type, .test_number, .status, .test_desc, .test_info[] | tostring ] | @csv' > ~/tmp/CIS.csv
```

3. Duplicate latest [spreadsheet sheet tab](https://docs.google.com/spreadsheets/d/1EfWeMMjOSH-zIdPAGjZBu8cHnt-_GNtXLngpRwtUG3M/edit) and import the CIS csv. To do it correctly, click in the `A2` cell and then go to `File > Import`, upload the csv from your computer and select `Replace data at selected cell` and separtor type `comma`.

4. Add conditional formatting in column `B`
| Color  | Rule  | Rule value  |
|---|---|---|
| green  | Text contains  |  PASS |
| yellow  | Text contains  |  WARN |
| red  | Text contains  |  FAIL |