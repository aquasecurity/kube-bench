---
name: Bug report
about: Tell us about a problem you are experiencing
---

**Overview**

[A clear and concise description of what the bug is] 

**How did you run kube-bench?**

[Please specify exactly how you ran kube-bench, including details of command parameters and/or job file that you used to run it]

**What happened?**

[Please include output from the report to illustrate the problem. If possible please supply logs generated with the `-v 3` parameter.]

**What did you expect to happen:**

[Please describe what you expected to happen differently.]

**Environment** 

[What is your version of kube-bench? (run `kube-bench version`)]

[What is your version of Kubernetes? (run `kubectl version` or `oc version` on OpenShift.)]

**Running processes**

[Please include the output from running `ps -eaf | grep kube` on the affected node. This will allow us to check what Kubernetes processes are running, and how this compares to what kube-bench detected.]

**Configuration files**

[If kube-bench is reporting an issue related to the settings defined in a config file, please attach the file, or include an extract showing the settings that are being detected incorrectly.]

**Anything else you would like to add:**

[Miscellaneous information that will assist in solving the issue.]
