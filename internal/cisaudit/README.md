# CIS 1.12 paginated audit collectors

Checks 5.1.3 and 5.1.6 now invoke the internal `kube-bench cis-audit`
command. Existing result fields, control IDs, and compliance predicates are
preserved, including the upstream wildcard-array matching and token truth table.
No other benchmark is changed. Existing Dockerfiles already include `internal/`
and `cmd/`, so no extra image dependency is needed.

Each API LIST request asks for 500 items, follows the server continuation
token, and has a 60-second timeout. The client-go transport uses explicit
KUBECONFIG when set, otherwise in-cluster service-account credentials, or the
standard local kubeconfig outside a pod. It preserves CA verification and token
file refresh, rejects redirects, and never defaults to localhost:8080.
An expired continuation token or any API/decode error aborts the check instead
of silently starting a new snapshot. Roles and ClusterRoles are evaluated directly
from their pages. ServiceAccount token settings are stored in a private temporary
directory and reused across Pods; files and staged findings are removed on normal
return. Abrupt process termination can leave temporary files until container cleanup.

Required access: list Roles and ClusterRoles cluster-wide, and list Pods and
ServiceAccounts cluster-wide. Listing ServiceAccounts is an additional requirement
compared with fetching individual ServiceAccounts. Missing accounts, forbidden
requests, malformed responses, and timeouts return nonzero; the existing unscored
CIS evaluator records WARN with an error reason, not PASS. A check warning does
not necessarily cause the entire kube-bench process to exit nonzero.

No cross-run cache is used. Individual paginated collections use the API's list
snapshot semantics; separate collections are not an atomic cluster-wide snapshot.
Run comparisons on a quiescent test cluster. Accounts deleted/created between
collections can produce a visible missing-account error.

Collector memory scales with a page rather than all cluster resources. This is
NOT an OOM guarantee: the parent kube-bench evaluator still stores audit output
and the JSON report in memory. Disk usage scales with accounts and findings.
The API request count is pages(Roles)+pages(ClusterRoles) for 5.1.3 and
pages(ServiceAccounts)+pages(Pods) for 5.1.6, rather than one GET per object/Pod.

Validation:

    go test ./internal/cisaudit ./check ./cmd
    docker build -t kube-bench:cis112-perf-test-1 .

Before changing the chart, compare the original and new images on the same test
fixtures, preserving node placement, benchmark and resource settings. Record scan
duration, image digest, memory history, audit request counts and complete reports.
Compare each control's status and findings, not only totals. Test denied list
permissions, timeouts and absent ServiceAccounts separately. Confirm AccuKnox
accepts the report. Unit tests include 8,008 Roles and all nine ServiceAccount/Pod
token combinations; these are not a real-cluster runtime or memory benchmark.
