# Integrating kube-bench with GCP Security Command Center

You can configure kube-bench with the `--gscc` to send findings to GCP Security Command Center (SCC). There are some additional steps required so that kube-bench has information and permissions to send these findings.

A few notes before getting started:

- There's multiple ways to assign pod identity in GCP. For this walkthrough we are using [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).
- The SCC `source` for kube-bench is created using a python script. This needs to be ran prior to executing kube-bench.
  - Creating sources is not currently supported in the gcloud cli.
  - Creating a source is an organizational permission, which is excessive for the kube-bench pod. This is why it is not part of the kube-bench application.

## Create the GCP SCC Source for kube-bench

This only needs to be done once per GCP organization.
This script requires the user to have the following perission: `securitycenter.sources.update` at the organization scope. The current role associated with this is `roles/securitycenter.sourcesEditor`

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r ./helper_scripts/create_gcp_source/requirements.txt
python ./helper_scripts/create_gcp_source/__main__.py <YOUR GCP ORG ID>
```

The output of this script is the name/id for the source. Format `organizations/<ORG_ID>/sources/<SOURCE_ID>`

## Enable API Access the GCP Security Command Center

_You will need GCP Security Command Center to be enabled in your project._

The details for assigning roles to the workload identity service account created by the job deployment is [documented here.](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#authenticating_to)
This step can be taken before you create the service account.

```bash
PROJECT_NUMBER="1234567890"
PROJECT_ID="my_gcp_project_id"
NAMESPACE="kube-bench"
KSA_NAME="kube-bench-sa"
ROLE="roles/securitycenter.findingsEditor"
gcloud projects add-iam-policy-binding projects/$PROJECT_ID --role=$ROLE \
    --member=principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$PROJECT_ID.svc.id.goog/subject/ns/$NAMESPACE/sa/$KSA_NAME
```

### Modify the job configuration

- Modify the kube-bench Configmap in `job-gke-stig-gscc.yaml` to specify the project ID, region, cluster name and source ID.
- In the same file, modify the image specifed in the Job to use the kube-bench image pushed to your GCP Artifact Registry.
- You may also need to modify the volume mount location for `kube-bench-gke-config` to match the version of the GKE STIG benchmark you are using.

You can now run kube-bench as a pod in your cluster: `kubectl apply -f job-gke-stig-gscc.yaml`

Findings will be generated for any kube-bench test that generates a `[FAIL]` or `[WARN]` output. If all tests pass, no findings will be generated. However, it's recommended that you consult the pod log output to check whether any findings were generated but could not be written to Security Command Center.

Query findings in SCC with the following:

```
state="ACTIVE" AND NOT mute="MUTED" AND parent_display_name="KubeBench" AND category="KUBERNETES_BENCHMARK"
```
