# Test and config files

`kube-bench` runs checks specified in `controls` files that are a YAML 
representation of the CIS Kubernetes Benchmark checks (or other distribution-specific hardening guides). 

## Controls

`controls` is a YAML document that contains checks that must be run against a 
specific Kubernetes node type, master or node and version.

`controls` is the fundamental input to `kube-bench`. The following is an example 
of a basic `controls`:

```yml
---
controls:
id: 1
text: "Master Node Security Configuration"
type: "master"
groups:
- id: 1.1
  text: API Server
  checks:
    - id: 1.1.1
      text: "Ensure that the --allow-privileged argument is set (Scored)"
      audit: "ps -ef | grep kube-apiserver | grep -v grep"
      tests:
      bin_op: or
      test_items:
      - flag: "--allow-privileged"
        set: true
      - flag: "--some-other-flag"
        set: false
      remediation: "Edit the /etc/kubernetes/config file on the master node and
        set the KUBE_ALLOW_PRIV parameter to '--allow-privileged=false'"
      scored: true
- id: 1.2
  text: Scheduler
  checks:
    - id: 1.2.1
      text: "Ensure that the --profiling argument is set to false (Scored)"
      audit: "ps -ef | grep kube-scheduler | grep -v grep"
      tests:
        bin_op: or
        test_items:
          - flag: "--profiling"
            set: true
          - flag: "--some-other-flag"
            set: false
      remediation: "Edit the /etc/kubernetes/config file on the master node and
        set the KUBE_ALLOW_PRIV parameter to '--allow-privileged=false'"
      scored: true
```

`controls` is composed of a hierarchy of groups, sub-groups and checks. Each of
the `controls` components have an id and a text description which are displayed 
in the `kube-bench` output.

`type` specifies what kubernetes node type a `controls` is for. Possible values
for `type` are `master` and `node`.

## Groups

`groups` is a list of subgroups that test the various Kubernetes components
that run on the node type specified in the `controls`. 

For example, one subgroup checks parameters passed to the API server binary, while 
another subgroup checks parameters passed to the controller-manager binary.

```yml
groups:
- id: 1.1
  text: API Server
  # ...
- id: 1.2
  text: Scheduler
  # ...
```

These subgroups have `id`, `text` fields which serve the same purposes described
in the previous paragraphs. The most important part of the subgroup is the
`checks` field which is the collection of actual `check`s that form the subgroup.

This is an example of a subgroup and checks in the subgroup.

```yml
id: 1.1
text: API Server
checks:
  - id: 1.1.1
    text: "Ensure that the --allow-privileged argument is set (Scored)"
    audit: "ps -ef | grep kube-apiserver | grep -v grep"
    tests:
    # ...
  - id: 1.1.2
    text: "Ensure that the --anonymous-auth argument is set to false (Not Scored)"
    audit: "ps -ef | grep kube-apiserver | grep -v grep"
    tests:
    # ...
``` 

`kube-bench` supports running a subgroup by specifying the subgroup `id` on the
command line, with the flag `--group` or `-g`.

## Check

The CIS Kubernetes Benchmark recommends configurations to harden Kubernetes components. These recommendations are usually configuration options and can be 
specified by flags to Kubernetes binaries, or in configuration files.

The Benchmark also provides commands to audit a Kubernetes installation, identify
places where the cluster security can be improved, and steps to remediate these
identified problems.

In `kube-bench`, `check` objects embody these recommendations.  This an example
`check` object:

```yml
id: 1.1.1
text: "Ensure that the --anonymous-auth argument is set to false (Not Scored)"
audit: "ps -ef | grep kube-apiserver | grep -v grep"
tests:
  test_items:
  - flag: "--anonymous-auth"
    compare:
      op: eq
      value: false
    set: true
remediation: |
  Edit the API server pod specification file kube-apiserver
  on the master node and set the below parameter.
  --anonymous-auth=false
scored: false
```

A `check` object has an `id`, a `text`, an `audit`, a `tests`, `remediation`
and `scored` fields.

`kube-bench` supports running individual checks by specifying the check's `id`
as a comma-delimited list on the command line with the `--check` flag.

The `audit` field specifies the command to run for a check. The output of this
command is then evaluated for conformance with the CIS Kubernetes Benchmark
recommendation.

The audit is evaluated against criteria specified by the `tests`
object. `tests` contain `bin_op` and `test_items`.

`test_items` specify the criteria(s) the `audit` command's output should meet to
pass a check. This criteria is made up of keywords extracted from the output of
the `audit` command and operations that compare these keywords against
values expected by the CIS Kubernetes Benchmark. 

There are three ways to extract keywords from the output of the `audit` command,
`flag`, `path`, `env`.

`flag` is used when the keyword is a command-line flag. The associated `audit`
command is usually a `ps` command and a `grep` for the binary whose flag we are
checking:

```sh
ps -ef | grep somebinary | grep -v grep
``` 

Here is an example usage of the `flag` option:

```yml
# ...
audit: "ps -ef | grep kube-apiserver | grep -v grep"
tests:
  test_items:
  - flag: "--anonymous-auth"
  # ...
```

`path` is used when the keyword is an option set in a JSON or YAML config file.
The associated `audit` command is usually `cat /path/to/config-yaml-or-json`.
For example:

```yml
# ...
text: "Ensure that the --anonymous-auth argument is set to false (Not Scored)"
audit: "cat /path/to/some/config"
tests:
  test_items:
  - path: "{.someoption.value}"
    # ...
```

`env` is used to check if the value is present within a specified environment variable. The presence of `env` is treated as an OR operation, if both `flag` and `env` are supplied it will use either to attempt pass the check.
The command used for checking the environment variables of a process **is generated by default**.

If the command being generated is causing errors, you can override the command used by setting `auditEnv` on the check.
Similarly, if you don't want the environment checking command to be generated or run at all, specify `disableEnvTesting` as true on the check.

The example below will check if the flag `--auto-tls` is equal to false *OR* `ETCD_AUTO_TLS` is equal to false

```yml
  test_items:
  - flag: "--auto-tls"
    env: "ETCD_AUTO_TLS"
    compare:
      op: eq
      value: false
```

`test_item` compares the output of the audit command and keywords using the
`set` and `compare` fields.

```yml
  test_items:
  - flag: "--anonymous-auth"
    compare:
      op: eq
      value: false
    set: true
```

`set` checks if a keyword is present in the output of the audit command or a config file. The possible values for `set` are true and false.

If `set` is true, the check passes only if the keyword is present in the output
of the audit command, or config file. If `set` is false, the check passes only
if the keyword is not present in the output of the audit command, or config file.

`compare` has two fields `op` and `value` to compare keywords with expected
value. `op` specifies which operation is used for the comparison, and `value`
specifies the value to compare against.

> To use `compare`, `set` must true. The comparison will be ignored if `set` is
> false

The `op` (operations) currently supported in `kube-bench` are:
- `eq`: tests if the keyword is equal to the compared value.
- `noteq`: tests if the keyword is unequal to the compared value.
- `gt`: tests if the keyword is greater than the compared value.
- `gte`: tests if the keyword is greater than or equal to the compared value.
- `lt`: tests if the keyword is less than the compared value.
- `lte`: tests if the keyword is less than or equal to the compared value.
- `has`: tests if the keyword contains the compared value.
- `nothave`: tests if the keyword does not contain the compared value.
- `regex`: tests if the flag value matches the compared value regular expression.
   When defining regular expressions in YAML it is generally easier to wrap them in
   single quotes, for example `'^[abc]$'`, to avoid issues with string escaping.

## Configuration and Variables

Kubernetes component configuration and binary file locations and names 
vary based on cluster deployment methods and Kubernetes distribution used.
For this reason, the locations of these binaries and config files are configurable
by editing the `cfg/config.yaml` file and these binaries and files can be
referenced in a `controls` file via variables.

The `cfg/config.yaml` file is a global configuration file. Configuration files
can be created for specific Kubernetes versions (distributions). Values in the
version-specific config overwrite similar values in `cfg/config.yaml`.

For example, the kube-apiserver in Red Hat OCP distribution is run as 
`hypershift openshift-kube-apiserver` instead of the default `kube-apiserver`.
This difference can be specified by editing the `master.apiserver.defaultbin`
entry `cfg/ocp-3.10/config.yaml`.

Below is the structure of `cfg/config.yaml`:

```
nodetype
  |-- components
    |-- component1
  |-- component1
    |-- bins
    |-- defaultbin (optional)
    |-- confs
    |-- defaultconf (optional)
    |-- svcs
    |-- defaultsvc (optional)
    |-- kubeconfig
    |-- defaultkubeconfig (optional)
```

Every node type has a subsection that specifies the main configuration items.

- `components`: A list of components for the node type. For example master 
  will have an entry for **apiserver**, **scheduler** and **controllermanager**.
  
  Each component has the following entries:

- `bins`: A list of candidate binaries for a component. `kube-bench` checks this
   list and selects the first binary that is running on the node.

   If none of the binaries in `bins` list is running, `kube-bench` checks if the
   binary specified by `defaultbin` is running and terminates if none of the 
   binaries in both `bins` and `defaultbin` is running.
   
   The selected binary for a component can be referenced in `controls` using a 
   variable in the form `$<component>bin`. In the example below, we reference 
   the selected API server binary with the variable `$apiserverbin` in an `audit`
   command.
   
   ```yml
   id: 1.1.1
    text: "Ensure that the --anonymous-auth argument is set to false (Scored)"
    audit: "ps -ef | grep $apiserverbin | grep -v grep"
    # ...
   ```
   
- `confs`: A list of candidate configuration files for a component. `kube-bench`
  checks this list and selects the first config file that is found on the node.
  If none of the config files exists, `kube-bench` defaults conf to the value
  of `defaultconf`.
  
  The selected config for a component can be referenced in `controls` using a
  variable in the form `$<component>conf`. In the example below, we reference the 
  selected API server config file with the variable `$apiserverconf` in an `audit`
  command.
  
  ```yml
  id: 1.4.1
    text: "Ensure that the API server pod specification file permissions are
    set to 644 or more restrictive (Scored)"
    audit: "/bin/sh -c 'if test -e $apiserverconf; then stat -c %a $apiserverconf; fi'"
  ```
  
- `svcs`:  A list of candidate unitfiles for a component. `kube-bench` checks this 
  list and selects the first unitfile that is found on the node. If none of the
  unitfiles exists, `kube-bench` defaults unitfile to the value of `defaultsvc`.
  
  The selected unitfile for a component can be referenced in `controls` via a
  variable in the form `$<component>svc`. In the example below, the selected 
  kubelet unitfile is referenced with `$kubeletsvc` in the `remediation` of the 
  `check`.
  
  ```yml
  id: 2.1.1
    # ...
    remediation: |
      Edit the kubelet service file $kubeletsvc
      on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.
      --allow-privileged=false
      Based on your system, restart the kubelet service. For example:
      systemctl daemon-reload
      systemctl restart kubelet.service
    # ...
  ```
  
  - `kubeconfig`: A list of candidate kubeconfig files for a component. `kube-bench`
    checks this list and selects the first file that is found on the node. If none
    of the files exists, `kube-bench` defaults kubeconfig to the value of 
    `defaultkubeconfig`.
    
    The selected kubeconfig for a component can be referenced in `controls` with a variable in the form `$<component>kubeconfig`. In the example below, the
    selected kubelet kubeconfig is referenced with `$kubeletkubeconfig` in the
    `audit` command.
    
    ```yml
    id: 2.2.1
      text: "Ensure that the kubelet.conf file permissions are set to 644 or
      more restrictive (Scored)"
      audit: "/bin/sh -c 'if test -e $kubeletkubeconfig; then stat -c %a $kubeletkubeconfig; fi'"
      # ...
    ```
